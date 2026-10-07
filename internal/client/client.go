// Package client is the command line terminal: it attaches the local TTY to
// a remote shell through the MikiSSh gateway.
//
//	mikissh client --url wss://gw.example/ssh --token $TOKEN
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Francis261/MikiSSh/internal/protocol"
	"github.com/coder/websocket"
	"golang.org/x/term"
)

// Options configures one client session.
type Options struct {
	URL      string
	Token    string
	Insecure bool
	Term     string
}

// Failure carries the process exit code. Printed reports whether the client
// already wrote the explanation to stderr, so main must not repeat it.
type Failure struct {
	Message string
	Code    int
	Printed bool
}

func (f *Failure) Error() string { return f.Message }

// Exit codes, matching the original client.
const (
	codeOK      = 0
	codeError   = 1
	codeDenied  = 77 // EX_NOPERM: policy rejected the session
	closeNormal = 1000
	closePolicy = 1008
)

const (
	handshakeTimeout = 10 * time.Second
	keepaliveEvery   = 25 * time.Second
	writeTimeout     = 10 * time.Second
	eofGrace         = 2 * time.Second
)

// Run dials the gateway and proxies the terminal until the session ends.
func Run(opts Options) error {
	if opts.URL == "" {
		return &Failure{Message: "--url is required", Code: codeError}
	}
	if opts.Token == "" {
		return &Failure{Message: "--token is required (or MIKISSH_TOKEN)", Code: codeError}
	}

	target, err := normaliseURL(opts.URL, opts.Insecure)
	if err != nil {
		return &Failure{Message: err.Error(), Code: codeError}
	}

	c := &cli{
		opts:   opts,
		authCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	c.detectTTY()

	conn, resp, err := c.dial(target)
	if err != nil {
		if resp != nil && resp.StatusCode > 0 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			c.fail(upgradeRejected(resp.StatusCode, strings.TrimSpace(string(body))), codeError)
			return c.result()
		}
		c.fail("connection failed: "+err.Error(), codeError)
		return c.result()
	}
	c.conn = conn

	c.status("handshaking…")
	go c.keepalive()
	go c.readStdinAfterAuth()

	return c.readLoop()
}

// normaliseURL maps http(s) onto ws(s) and enforces the TLS policy.
func normaliseURL(raw string, insecure bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid --url: %w", err)
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}
	if u.Scheme == "wss" {
		return u, nil
	}
	// Plain ws:// is allowed only with an explicit --insecure opt-in. The
	// normal case is probing the gateway's loopback origin directly, where
	// TLS is terminated by the tunnel or reverse proxy in front of it.
	if u.Scheme != "ws" || !insecure {
		return nil, fmt.Errorf("refusing non-TLS endpoint: use wss:// (or https://). " +
			"Pass --insecure to allow ws:// for local origin testing.")
	}
	return u, nil
}

// upgradeRejected renders the same explanation the original client did.
func upgradeRejected(status int, body string) string {
	hint := ""
	switch {
	case status == 404:
		hint = " — wrong URL path; the endpoint is /ssh"
	case status >= 500:
		hint = " — the edge could not reach the gateway"
	}
	msg := fmt.Sprintf("gateway rejected upgrade (HTTP %d)%s", status, hint)
	if body != "" {
		msg += "\n  " + strings.ReplaceAll(body, "\n", "\n  ")
	}
	return msg
}

// cli holds the mutable state of one session.
type cli struct {
	opts Options
	conn *websocket.Conn

	// writeMu serialises frames from the reader loop, the stdin pump, the
	// resize watcher and the keepalive ticker.
	writeMu sync.Mutex

	mu       sync.Mutex
	authed   bool
	done     bool
	wrote    bool
	exitCode int

	useTty  bool
	cols    int
	rows    int
	restore func()

	authOnce sync.Once
	authCh   chan struct{}
	doneCh   chan struct{}
}

func (c *cli) dial(target *url.URL) (*websocket.Conn, *http.Response, error) {
	// Only bounds the handshake: coder's Dial cancels its own context
	// before returning, so the session is not tied to this deadline.
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: c.opts.Insecure},
		},
	}
	return websocket.Dial(ctx, target.String(), &websocket.DialOptions{
		Subprotocols: []string{"mikissh", "t." + c.opts.Token},
		HTTPClient:   httpClient,
	})
}

func (c *cli) detectTTY() {
	inFd, outFd := int(os.Stdin.Fd()), int(os.Stdout.Fd())
	c.useTty = term.IsTerminal(inFd) && term.IsTerminal(outFd)
	c.cols, c.rows = 80, 24
	if w, h, err := term.GetSize(outFd); err == nil && w > 0 && h > 0 {
		c.cols, c.rows = w, h
	}
}

// size re-queries the terminal so a resize is picked up immediately.
func (c *cli) size() (int, int) {
	outFd := int(os.Stdout.Fd())
	if w, h, err := term.GetSize(outFd); err == nil && w > 0 && h > 0 {
		return w, h
	}
	return c.cols, c.rows
}

func (c *cli) terminalName() string {
	if c.opts.Term != "" {
		return c.opts.Term
	}
	if t := os.Getenv("TERM"); t != "" {
		return t
	}
	return "xterm-256color"
}

// readLoop dispatches frames until the connection ends.
func (c *cli) readLoop() error {
	for {
		msgType, data, err := c.conn.Read(context.Background())
		if err != nil {
			if code := websocket.CloseStatus(err); code >= 0 {
				return c.onClose(int(code))
			}
			_ = msgType
			c.fail("connection failed: "+err.Error(), codeError)
			return c.result()
		}

		msg, err := protocol.Decode(data)
		if err != nil {
			c.fail("protocol error", codeError)
			return c.result()
		}

		switch msg.Type {
		case protocol.TypeKex:
			cols, rows := c.size()
			c.sendJSON(protocol.TypeAuthRequest, map[string]any{
				"term": c.terminalName(),
				"cols": cols,
				"rows": rows,
			})

		case protocol.TypeAuthOK:
			c.onAuthed()

		case protocol.TypeAuthFail:
			var f struct {
				Reason string `json:"reason"`
			}
			_ = msg.JSON(&f)
			reason := f.Reason
			if reason == "" {
				reason = "rejected"
			}
			c.fail("unauthorized: "+reason, codeDenied)
			return c.result()

		case protocol.TypeStdout, protocol.TypeStderr:
			if _, err := os.Stdout.Write(msg.Payload); err == nil {
				c.mu.Lock()
				c.wrote = true
				c.mu.Unlock()
			}

		case protocol.TypeExit:
			return c.onExit(msg)

		case protocol.TypeError:
			var e struct {
				Message string `json:"message"`
			}
			_ = msg.JSON(&e)
			c.newlineIfWrote()
			fmt.Printf("[error] %s\n", e.Message)

		case protocol.TypePong:
			// keepalive reply
		}
	}
}

func (c *cli) onExit(msg *protocol.Message) error {
	var x struct {
		Code   *int    `json:"code"`
		Signal *string `json:"signal"`
	}
	_ = msg.JSON(&x)

	code := 0
	if x.Code != nil {
		code = *x.Code
	}
	c.newlineIfWrote()
	if x.Signal != nil && *x.Signal != "" {
		fmt.Printf("[session ended: signal %s]\n", *x.Signal)
	} else {
		fmt.Printf("[session ended: code %d]\n", code)
	}

	exit := codeError
	if code == 0 {
		exit = codeOK
	}
	c.finish(exit)
	return c.result()
}

// onClose maps a close code onto a process exit code.
func (c *cli) onClose(code int) error {
	if !c.claimed() {
		c.newlineIfWrote()
		c.status(fmt.Sprintf("disconnected (%d)", code))
		fmt.Fprintln(os.Stderr)

		exit := codeError
		switch code {
		case closeNormal:
			exit = codeOK
		case closePolicy:
			// 1008 = policy violation: bad token, bad origin, or rate
			// limited.
			exit = codeDenied
		}
		c.finish(exit)
	}
	return c.result()
}

func (c *cli) onAuthed() {
	c.authOnce.Do(func() {
		c.mu.Lock()
		c.authed = true
		c.mu.Unlock()

		c.status("connected")
		// Wake the stdin pump now that keystrokes mean something.
		close(c.authCh)
		if c.useTty {
			fd := int(os.Stdin.Fd())
			if st, err := term.MakeRaw(fd); err == nil {
				c.restore = func() { _ = term.Restore(fd, st) }
			}
			go c.watchResize()
		}
		c.sendResize()
	})
}

// ------------------------------------------------------------- frame output

func (c *cli) sendJSON(t protocol.Type, v any) {
	frame, err := protocol.EncodeJSON(t, v)
	if err != nil {
		return
	}
	c.send(frame)
}

func (c *cli) send(frame []byte) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	// A failed write means the peer is already gone; the read loop reports
	// the actual cause, so this stays silent.
	_ = c.conn.Write(ctx, websocket.MessageBinary, frame)
}

func (c *cli) sendResize() {
	c.mu.Lock()
	authed := c.authed
	c.mu.Unlock()
	if !authed {
		return
	}
	w, h := c.size()
	if frame, err := protocol.EncodeResize(w, h); err == nil {
		c.send(frame)
	}
}

func (c *cli) keepalive() {
	t := time.NewTicker(keepaliveEvery)
	defer t.Stop()
	for range t.C {
		c.mu.Lock()
		authed, done := c.authed, c.done
		c.mu.Unlock()
		if done {
			return
		}
		if !authed {
			continue
		}
		if frame, err := protocol.Encode(protocol.TypePing, nil); err == nil {
			c.send(frame)
		}
	}
}

// readStdinAfterAuth starts pumping stdin once the session is up; the
// original never read the terminal before authentication either.
func (c *cli) readStdinAfterAuth() {
	// Wait for auth, or for the session to end.
	select {
	case <-c.authCh:
	case <-c.doneCh:
		return
	}

	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			if frame, e := protocol.Encode(protocol.TypeStdin, buf[:n]); e == nil {
				c.send(frame)
			}
		}
		if err != nil {
			if !c.useTty {
				c.handleEOF()
			}
			return
		}
	}
}

// handleEOF forwards Ctrl-D to the remote shell and hangs up shortly after,
// so piped input (`echo cmd | mikissh client ...`) still terminates.
func (c *cli) handleEOF() {
	c.mu.Lock()
	authed, done := c.authed, c.done
	c.mu.Unlock()
	if !authed || done {
		return
	}
	if frame, err := protocol.Encode(protocol.TypeStdin, []byte{0x04}); err == nil {
		c.send(frame)
	}
	time.AfterFunc(eofGrace, func() { c.finish(codeOK) })
}

// ----------------------------------------------------------------- output

func (c *cli) status(text string) {
	c.mu.Lock()
	wrote := c.wrote
	c.mu.Unlock()
	if wrote {
		fmt.Fprintf(os.Stderr, "\r\x1b[2K\x1b[33mmikissh: %s\x1b[0m", text)
		return
	}
	fmt.Fprintf(os.Stderr, "\r\x1b[2Kmikissh: %s", text)
}

// fail reports a fatal problem exactly once. A follow-on socket error must
// not overwrite the real cause.
func (c *cli) fail(message string, code int) {
	if !c.claim(code) {
		return
	}
	fmt.Fprintf(os.Stderr, "\r\x1b[2Kmikissh: %s\n", message)
	c.shutdown()
}

// finish ends the session with the given exit code, printing nothing.
func (c *cli) finish(code int) {
	if !c.claim(code) {
		return
	}
	c.shutdown()
}

// claim records the exit code, reporting whether this call won the race.
func (c *cli) claim(code int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return false
	}
	c.done = true
	c.exitCode = code
	if c.doneCh != nil {
		close(c.doneCh)
	}
	return true
}

func (c *cli) claimed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.done
}

func (c *cli) shutdown() {
	if c.restore != nil {
		c.restore()
		c.restore = nil
	}
	if c.conn != nil {
		// Additional Close calls are no-ops, so this is safe if the server
		// already started the handshake.
		_ = c.conn.Close(websocket.StatusNormalClosure, "")
	}
}

func (c *cli) newlineIfWrote() {
	c.mu.Lock()
	wrote := c.wrote
	c.mu.Unlock()
	if wrote {
		fmt.Println()
	}
}

// result turns the recorded exit code into the error main acts on.
func (c *cli) result() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.exitCode == 0 {
		return nil
	}
	// Everything relevant has already been written to stderr or stdout.
	return &Failure{Code: c.exitCode, Printed: true}
}
