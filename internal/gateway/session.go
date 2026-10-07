package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Francis261/MikiSSh/internal/bridge"
	"github.com/Francis261/MikiSSh/internal/logger"
	"github.com/Francis261/MikiSSh/internal/protocol"
	"github.com/coder/websocket"
)

// Session is one authenticated terminal.
type Session struct {
	id  string
	ip  string
	log *logger.Logger
	gw  *Gateway
	ws  *websocket.Conn

	// writeMu serialises every frame so close frames always follow the
	// data they are terminating, rather than interleaving with it.
	writeMu sync.Mutex

	closeOnce sync.Once
	cleanOnce sync.Once

	mu        sync.Mutex
	st        sessionState
	bridge    *bridge.Bridge
	idleTimer *time.Timer
	guard     *time.Timer
}

// run sends the greeting and then processes frames until the peer hangs up.
func (s *Session) run() {
	s.send(protocol.MustEncodeJSON(protocol.TypeKex, map[string]any{
		"server":  "mikissh",
		"version": Version,
	}))
	s.armIdle()
	defer s.finishRead()

	for {
		msgType, data, err := s.ws.Read(context.Background())
		if err != nil {
			// Peer hung up, idle timeout fired, or the transport failed.
			// Either way the read loop is over and cleanup runs below.
			return
		}
		s.armIdle()

		msg, err := protocol.Decode(data)
		if err != nil {
			if protocol.IsProtocolError(err) {
				s.log.Warn("protocol violation", logger.F("err", err.Error()))
				s.closeWith(1002, "protocol error")
				return
			}
			s.closeWith(1011, "internal error")
			return
		}

		if msgType != websocket.MessageBinary && msg.Type != protocol.TypeAuthRequest {
			s.log.Warn("non-binary frame rejected")
			s.closeWith(1002, "binary frames required")
			return
		}

		if err := s.handle(msg); err != nil {
			s.log.Error("handler failure", logger.F("err", err.Error()))
			s.send(protocol.MustEncodeJSON(protocol.TypeError,
				map[string]any{"message": "internal error"}))
		}
	}
}

// handle dispatches one frame.
func (s *Session) handle(msg *protocol.Message) error {
	switch msg.Type {
	case protocol.TypeAuthRequest:
		return s.handleAuth(msg)

	case protocol.TypeStdin:
		if b, ok := s.readyBridge(); ok {
			b.Write(msg.Payload)
		}
		return nil

	case protocol.TypeResize:
		if _, ok := s.readyBridge(); !ok {
			return nil
		}
		cols, rows, err := protocol.DecodeResize(msg.Payload)
		if err != nil {
			// Surfaced to the caller, which replies with an ERROR frame.
			return err
		}
		s.bridgeRef().Resize(int(cols), int(rows))
		return nil

	case protocol.TypePing:
		pong, _ := protocol.Encode(protocol.TypePong, msg.Payload)
		s.send(pong)
		return nil

	default:
		s.log.Warn("unknown message type", logger.F("type", msg.TypeName))
		s.send(protocol.MustEncodeJSON(protocol.TypeError,
			map[string]any{"message": "unknown type " + msg.TypeName}))
		return nil
	}
}

// handleAuth opens the backend SSH connection for this session.
func (s *Session) handleAuth(msg *protocol.Message) error {
	if !s.transition(statePending, stateConnecting) {
		// Deliberately matches the original: any second AUTH_REQUEST, once
		// the handshake has moved on, is refused rather than re-run.
		s.send(protocol.MustEncodeJSON(protocol.TypeAuthFail,
			map[string]any{"reason": "already authenticated"}))
		return nil
	}

	var opts struct {
		Term json.RawMessage `json:"term"`
		Cols json.RawMessage `json:"cols"`
		Rows json.RawMessage `json:"rows"`
	}
	if err := msg.JSON(&opts); err != nil {
		s.setState(stateFailed)
		return err
	}

	term := sanitizeTerm(opts.Term)
	cols := coerceInt(opts.Cols, 1, 500, 80)
	rows := coerceInt(opts.Rows, 1, 200, 24)

	b := bridge.New(&s.gw.cfg.SSH, bridge.Options{
		Term:       term,
		Cols:       cols,
		Rows:       rows,
		PrivateKey: s.gw.pkey,
	}, s.log)
	s.setBridge(b)

	// A handshake that never completes must still be refused, so the client
	// is not left waiting on a dead backend.
	guard := time.AfterFunc(25*time.Second, func() {
		s.sshFailed(errors.New("ssh timeout"))
	})
	s.setGuard(guard)

	b.OnReady = func() {
		if !s.transition(stateConnecting, stateReady) {
			// Lost the race with the guard timer or a failure.
			return
		}
		guard.Stop()
		s.log.Info("ssh session ready")
		s.send(protocol.MustEncodeJSON(protocol.TypeAuthOK,
			map[string]any{"sessionId": s.id}))
	}
	b.OnError = s.sshFailed
	b.OnStdout = func(p []byte) {
		if frame, err := protocol.Encode(protocol.TypeStdout, p); err == nil {
			s.send(frame)
		}
	}
	b.OnStderr = func(p []byte) {
		if frame, err := protocol.Encode(protocol.TypeStderr, p); err == nil {
			s.send(frame)
		}
	}
	b.OnExit = func(code int, signal string) {
		var sig any
		if signal != "" {
			sig = signal
		}
		s.send(protocol.MustEncodeJSON(protocol.TypeExit,
			map[string]any{"code": code, "signal": sig}))
	}
	// The server reported an exit: the WebSocket stays open so the client
	// can read the exit frame and hang up itself.
	b.OnClose = func() { s.closeWith(1000, "shell exited") }

	b.Connect()
	return nil
}

// sshFailed handles a backend failure. Before the handshake completes it
// refuses the session; afterwards it only reports the error on the stream.
func (s *Session) sshFailed(err error) {
	if err == nil {
		return
	}
	if s.state() == stateReady {
		s.log.Warn("ssh error", logger.F("err", err.Error()))
		s.send(protocol.MustEncodeJSON(protocol.TypeError,
			map[string]any{"message": "ssh error"}))
		return
	}
	// Only the first failure is acted on; later ones are already covered.
	if !s.transition(stateConnecting, stateFailed) {
		return
	}
	s.clearGuard()
	s.log.Warn("ssh handshake failed", logger.F("err", err.Error()))
	// Opaque to the client: SSH errors can be verbose.
	s.send(protocol.MustEncodeJSON(protocol.TypeAuthFail,
		map[string]any{"reason": "ssh connection failed"}))
	if b := s.bridgeRef(); b != nil {
		b.Close()
	}
	s.closeWith(1002, "auth failed")
}

// ---------------------------------------------------------------- lifecycle

// closeWith sends a close frame exactly once, then tears the session down.
func (s *Session) closeWith(code int, reason string) {
	s.closeOnce.Do(func() {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		// Close waits for the peer's close frame, which is why the write
		// lock is held: the frame must not interleave with live data.
		_ = s.ws.Close(websocket.StatusCode(code), reason)
	})
	s.cleanup()
}

// finishRead is the read loop's exit path.
func (s *Session) finishRead() {
	s.closeOnce.Do(func() {
		// Nothing will write again, so release the socket immediately.
		_ = s.ws.CloseNow()
	})
	s.cleanup()
}

func (s *Session) cleanup() {
	s.cleanOnce.Do(func() {
		s.clearTimers()
		s.setState(stateClosed)
		if b := s.bridgeRef(); b != nil {
			b.Close()
		}
		s.gw.untrack(s)
		s.log.Info("session closed")
	})
}

// send writes one framed message, bounded so a stalled peer cannot hold the
// session lock forever.
func (s *Session) send(frame []byte) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	if err := s.ws.Write(ctx, websocket.MessageBinary, frame); err != nil {
		// A failed write means the peer is already gone; the read loop
		// reports the actual cause.
		s.log.Debug("write failed", logger.F("err", err.Error()))
	}
}

// closeConn rejects a connection that never became a session, where no
// session-level locking exists yet.
func closeConn(ws *websocket.Conn, code int, reason string) {
	_ = ws.Close(websocket.StatusCode(code), reason)
}

// ------------------------------------------------------------------ helpers

func (s *Session) state() sessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

func (s *Session) setState(st sessionState) {
	s.mu.Lock()
	s.st = st
	s.mu.Unlock()
}

// transition moves the state only if it currently equals from.
func (s *Session) transition(from, to sessionState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st != from {
		return false
	}
	s.st = to
	return true
}

func (s *Session) setBridge(b *bridge.Bridge) {
	s.mu.Lock()
	s.bridge = b
	s.mu.Unlock()
}

func (s *Session) bridgeRef() *bridge.Bridge {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bridge
}

// readyBridge returns the bridge only once the session is fully up.
func (s *Session) readyBridge() (*bridge.Bridge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st != stateReady || s.bridge == nil {
		return nil, false
	}
	return s.bridge, true
}

func (s *Session) setGuard(t *time.Timer) {
	s.mu.Lock()
	s.guard = t
	s.mu.Unlock()
}

func (s *Session) clearGuard() {
	s.mu.Lock()
	if s.guard != nil {
		s.guard.Stop()
		s.guard = nil
	}
	s.mu.Unlock()
}

func (s *Session) clearTimers() {
	s.mu.Lock()
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	if s.guard != nil {
		s.guard.Stop()
		s.guard = nil
	}
	s.mu.Unlock()
}

// armIdle restarts the inactivity deadline. Any inbound frame counts as
// activity, so an active terminal is never cut off.
func (s *Session) armIdle() {
	d := time.Duration(s.gw.cfg.Security.IdleTimeoutMs) * time.Millisecond
	if d <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	s.idleTimer = time.AfterFunc(d, func() {
		s.log.Info("idle timeout")
		s.send(protocol.MustEncodeJSON(protocol.TypeError,
			map[string]any{"message": "idle timeout"}))
		s.closeWith(1000, "idle timeout")
	})
}

// --------------------------------------------------------- input sanitising

var termPattern = regexp.MustCompile(`^[\w.-]{1,40}$`)

// sanitizeTerm accepts only a conservative terminal name, so a client can
// never smuggle arbitrary bytes into the pty request.
func sanitizeTerm(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "xterm-256color"
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "xterm-256color"
	}
	var s string
	switch t := v.(type) {
	case string:
		s = t
	case nil:
		return "xterm-256color"
	case float64:
		s = strconv.FormatFloat(t, 'g', -1, 64)
	case bool:
		s = strconv.FormatBool(t)
	default:
		return "xterm-256color"
	}
	if termPattern.MatchString(s) {
		return s
	}
	return "xterm-256color"
}

// coerceInt mirrors the original numeric coercion: absent or non-finite
// input falls back to the default, everything else is truncated and clamped.
func coerceInt(raw json.RawMessage, min, max, dflt int) int {
	if len(raw) == 0 {
		return dflt
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return dflt
	}
	n, ok := jsNumber(v)
	if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
		return dflt
	}
	i := int(n) // truncates toward zero, like Math.trunc
	if i < min {
		return min
	}
	if i > max {
		return max
	}
	return i
}

// jsNumber reproduces JavaScript's Number() for the JSON value kinds a
// client can actually send.
func jsNumber(v any) (float64, bool) {
	switch t := v.(type) {
	case nil:
		return 0, true // Number(null)
	case float64:
		return t, true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, true // Number('')
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, false // Number('abc') is NaN
		}
		return f, true
	default:
		return 0, false // objects and arrays are NaN
	}
}
