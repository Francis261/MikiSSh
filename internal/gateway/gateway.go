// Package gateway runs the WebSocket front end: TLS policy, authentication,
// session limits, and the bridge from each terminal session to the backend
// SSH server.
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Francis261/MikiSSh/internal/auth"
	"github.com/Francis261/MikiSSh/internal/config"
	"github.com/Francis261/MikiSSh/internal/logger"
	"github.com/Francis261/MikiSSh/internal/protocol"
	"github.com/Francis261/MikiSSh/internal/static"
	"github.com/Francis261/MikiSSh/internal/tlsutil"
	"github.com/Francis261/MikiSSh/public"
	"github.com/coder/websocket"
)

// Version is reported in the KEX greeting. It is a var so release builds can
// stamp it from the git tag with -ldflags -X.
var Version = "0.1.0"

// subprotocol is the only WebSocket subprotocol this gateway accepts.
const subprotocol = "mikissh"

// writeTimeout bounds a single frame write so a wedged peer can never hold
// the session lock indefinitely.
const writeTimeout = 10 * time.Second

// sessionState tracks a session's progress through the handshake.
type sessionState int

const (
	statePending sessionState = iota
	stateConnecting
	stateReady
	stateFailed
	stateClosed
)

func (s sessionState) String() string {
	switch s {
	case statePending:
		return "pending"
	case stateConnecting:
		return "connecting"
	case stateReady:
		return "ready"
	case stateFailed:
		return "failed"
	case stateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// Gateway owns both listeners and every live session.
type Gateway struct {
	cfg   *config.Config
	log   *logger.Logger
	authz *auth.Authorizer
	pkey  []byte
	ui    *static.Handler

	mu       sync.Mutex
	sessions map[string]*Session

	tlsSrv    *http.Server
	plainSrv  *http.Server
	tlsLn     net.Listener
	plainLn   net.Listener
	sweepStop chan struct{}
	started   bool
}

// New validates the configuration and prepares the gateway without binding
// any socket.
func New(cfg *config.Config, log *logger.Logger) (*Gateway, error) {
	if cfg.WS.TLS.Cert == "" || cfg.WS.TLS.Key == "" {
		return nil, errors.New("TLS certificate and key are required (WSS only, no plaintext mode)")
	}

	// Relative paths resolve against the project root rather than the
	// process working directory, so the gateway behaves identically whether
	// it is started by pm2, by a systemd unit, or by `go test`.
	root := config.FindRoot()
	cfg.WS.TLS.Cert = config.ResolveAgainst(root, cfg.WS.TLS.Cert)
	cfg.WS.TLS.Key = config.ResolveAgainst(root, cfg.WS.TLS.Key)
	if cfg.SSH.PrivateKey != "" {
		cfg.SSH.PrivateKey = config.ResolveAgainst(root, cfg.SSH.PrivateKey)
	}
	if cfg.SSH.KnownHosts != "" {
		cfg.SSH.KnownHosts = config.ResolveAgainst(root, cfg.SSH.KnownHosts)
	}

	pkey, err := config.ResolvePrivateKey(cfg)
	if err != nil {
		return nil, err
	}

	ui, err := static.New(root+"/public", cfg.UIEnabled(), public.FS)
	if err != nil {
		return nil, err
	}

	if log == nil {
		log = logger.New(cfg.Log.Level, nil)
	}

	return &Gateway{
		cfg: cfg,
		log: log.With(logger.F("comp", "gateway")),
		authz: auth.New(cfg.Auth.Tokens, cfg.Auth.Required, cfg.Auth.MaxAttempts,
			time.Duration(cfg.Auth.WindowMs)*time.Millisecond),
		pkey:     pkey,
		ui:       ui,
		sessions: make(map[string]*Session),
	}, nil
}

// Start binds the TLS listener and, when configured, the loopback-only
// plain listener. It returns the address of the TLS listener.
func (g *Gateway) Start() (net.Addr, error) {
	g.mu.Lock()
	if g.started {
		g.mu.Unlock()
		return nil, errors.New("gateway already started")
	}
	g.mu.Unlock()

	// Validate before binding anything: a rejected configuration must not
	// leave a half-open listener behind.
	if g.cfg.WS.LoopbackHTTP.Enabled {
		if err := config.AssertLoopback(g.cfg.WS.LoopbackHTTP.Host); err != nil {
			return nil, err
		}
	}

	if !g.authz.Configured() {
		g.log.Warn("no auth tokens configured — all authenticated handshakes will be rejected (fail closed)")
	}
	if len(g.cfg.Security.AllowedOrigins) == 0 {
		g.log.Warn("no origin allowlist configured — set security.allowedOrigins to block cross-site WebSockets")
	}

	cert, key, _, err := tlsutil.Ensure(g.cfg.WS.TLS.Cert, g.cfg.WS.TLS.Key, "localhost", g.log)
	if err != nil {
		return nil, err
	}
	// Keep the config consistent with what is actually on disk.
	g.cfg.WS.TLS.Cert = cert
	g.cfg.WS.TLS.Key = key

	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("load TLS material: %w", err)
	}

	// The public listener is TLS 1.3 only, regardless of what a config file
	// asks for: there is no plaintext mode to fall back to.
	if !strings.EqualFold(g.cfg.WS.TLS.MinVersion, "TLSv1.3") &&
		!strings.EqualFold(g.cfg.WS.TLS.MinVersion, "TLSv13") {
		g.log.Warn("tls.minVersion is not TLSv1.3 — enforcing TLS 1.3 anyway",
			logger.F("configured", g.cfg.WS.TLS.MinVersion))
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
		// Advertise HTTP/1.1 only: WebSocket needs a hijackable response
		// writer, which HTTP/2 does not provide here.
		NextProtos: []string{"http/1.1"},
	}

	router := http.HandlerFunc(g.route)

	ln, err := net.Listen("tcp", net.JoinHostPort(g.cfg.WS.Host, strconv.Itoa(g.cfg.WS.Port)))
	if err != nil {
		return nil, fmt.Errorf("listen %s:%d: %w", g.cfg.WS.Host, g.cfg.WS.Port, err)
	}
	tlsLn := tls.NewListener(ln, tlsCfg)

	tlsSrv := &http.Server{
		Handler: router,
		// A non-nil (empty) map disables Go's automatic HTTP/2 setup.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		// Upgrades are long-lived by nature; idle timeouts belong to the
		// application, not the server.
		ReadHeaderTimeout: 15 * time.Second,
	}

	g.mu.Lock()
	g.tlsLn, g.tlsSrv, g.started = tlsLn, tlsSrv, true
	g.mu.Unlock()

	go g.serve("tls", tlsSrv, tlsLn)

	if loop := g.cfg.WS.LoopbackHTTP; loop.Enabled {
		plainLn, err := net.Listen("tcp", net.JoinHostPort(loop.Host, strconv.Itoa(loop.Port)))
		if err != nil {
			_ = tlsLn.Close()
			return nil, fmt.Errorf("listen %s:%d: %w", loop.Host, loop.Port, err)
		}
		plainSrv := &http.Server{
			Handler:           router,
			TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
			ReadHeaderTimeout: 15 * time.Second,
		}
		g.mu.Lock()
		g.plainLn, g.plainSrv = plainLn, plainSrv
		g.mu.Unlock()
		go g.serve("plain", plainSrv, plainLn)

		g.log.Warn("plain HTTP listener enabled — TLS MUST be terminated upstream",
			logger.F("addr", net.JoinHostPort(loop.Host, strconv.Itoa(loop.Port))),
			logger.F("setOriginTo", fmt.Sprintf("http://%s%s", net.JoinHostPort(loop.Host, strconv.Itoa(loop.Port)), g.cfg.WS.Path)))
	}

	g.sweepStop = make(chan struct{})
	go g.sweep(g.sweepStop)

	g.log.Info("listening",
		logger.F("addr", tlsLn.Addr().String()),
		logger.F("path", g.cfg.WS.Path),
		logger.F("tls", "TLSv1.3"),
		logger.F("sshTarget", fmt.Sprintf("%s@%s:%d",
			g.cfg.SSH.Username, g.cfg.SSH.Host, g.cfg.SSH.Port)),
	)

	return tlsLn.Addr(), nil
}

// serve runs an http.Server, logging unexpected failures.
func (g *Gateway) serve(name string, srv *http.Server, ln net.Listener) {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		g.log.Error("%s listener stopped", logger.F("err", err.Error()), logger.F("listener", name))
	}
}

func (g *Gateway) sweep(stop chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			g.authz.Sweep()
		}
	}
}

// Stop closes every session and both listeners. It is safe to call twice.
func (g *Gateway) Stop() error {
	g.mu.Lock()
	started := g.started
	g.started = false
	sessions := make([]*Session, 0, len(g.sessions))
	for _, s := range g.sessions {
		sessions = append(sessions, s)
	}
	sweepStop, plainSrv, tlsSrv, plainLn, tlsLn :=
		g.sweepStop, g.plainSrv, g.tlsSrv, g.plainLn, g.tlsLn
	g.sweepStop, g.plainSrv, g.tlsSrv, g.plainLn, g.tlsLn = nil, nil, nil, nil, nil
	g.mu.Unlock()

	if !started {
		return nil
	}
	if sweepStop != nil {
		select {
		case <-sweepStop:
		default:
			close(sweepStop)
		}
	}

	// Close sessions concurrently: each close waits for the peer's close
	// frame, and serialising them would make shutdown needlessly slow.
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Add(1)
		go func(s *Session) {
			defer wg.Done()
			s.closeWith(1001, "server shutdown")
		}(s)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, srv := range []*http.Server{plainSrv, tlsSrv} {
		if srv == nil {
			continue
		}
		if err := srv.Shutdown(ctx); err != nil {
			_ = srv.Close()
		}
	}
	for _, ln := range []net.Listener{plainLn, tlsLn} {
		if ln != nil {
			_ = ln.Close()
		}
	}
	return nil
}

// Addr reports the bound TLS address, or nil before Start.
func (g *Gateway) Addr() net.Addr {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.tlsLn == nil {
		return nil
	}
	return g.tlsLn.Addr()
}

// route sends upgrades to the WebSocket path and everything else to the UI.
//
// This mirrors the original split between an "upgrade" listener and a
// request listener: a plain GET to /ssh is a static 404, while an upgrade at
// the wrong path gets an explanatory 404.
func (g *Gateway) route(w http.ResponseWriter, r *http.Request) {
	if isWebSocketUpgrade(r) {
		g.handleUpgrade(w, r)
		return
	}
	g.ui.ServeHTTP(w, r)
}

func (g *Gateway) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	// ws and net/http do not enforce a path, so do it here.
	if r.URL.Path != g.cfg.WS.Path {
		body := fmt.Sprintf("MikiSSh: no WebSocket endpoint at %s.\nThe endpoint is %s, e.g. wss://<host>%s\n",
			r.URL.Path, g.cfg.WS.Path, g.cfg.WS.Path)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusNotFound)
		// Writing the whole body through the response writer guarantees it
		// is flushed: a truncated reply is reported by proxies in front
		// (cloudflared, nginx) as 502 instead of this 404.
		_, _ = io.WriteString(w, body)
		return
	}

	if !offersSubprotocol(r.Header.Get("Sec-WebSocket-Protocol"), subprotocol) {
		http.Error(w, "the "+subprotocol+" subprotocol is required", http.StatusBadRequest)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{subprotocol},
		// Origin policy is enforced in serve(), where the original applied
		// its own allowlist; Accept's built-in host match is too strict for
		// a TLS-terminating tunnel in front of us.
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		// Accept has already replied; nothing further to write.
		return
	}
	conn.SetReadLimit(protocol.MaxFrameBytes + 1)

	g.serveSession(conn, r)
}

// serveSession runs the pre-session policy checks and then the read loop.
func (g *Gateway) serveSession(ws *websocket.Conn, r *http.Request) {
	ip := clientIP(r)
	log := g.log.With(logger.F("ip", ip), logger.F("conn", randomHex(4)))

	// --- 1. Origin check ---------------------------------------------------
	origin := r.Header.Get("Origin")
	if !g.originAllowed(origin) {
		log.Warn("rejected origin", logger.F("origin", origin))
		closeConn(ws, 1008, "origin not allowed")
		return
	}

	// --- 2. Token check ----------------------------------------------------
	token, _ := auth.ExtractToken(
		r.Header.Get("Sec-WebSocket-Protocol"), r.URL.RawQuery)
	tokenFp := "none"
	if token != "" {
		tokenFp = auth.Fingerprint(token)
	}
	if verdict := g.authz.Check(ip, token); !verdict.OK {
		// Deliberately opaque: never reveal which check failed.
		log.Warn("auth rejected",
			logger.F("reason", verdict.Reason),
			logger.F("tokenFp", tokenFp))
		closeConn(ws, 1008, "unauthorized")
		return
	}

	// --- 3. Session limits -------------------------------------------------
	if code, reason, ok := g.admit(ip); !ok {
		closeConn(ws, code, reason)
		return
	}

	log.Info("session authorized", logger.F("tokenFp", tokenFp))

	s := &Session{
		id:  randomHex(16),
		ip:  ip,
		log: log,
		gw:  g,
		ws:  ws,
	}
	g.track(s)
	s.run()
}

// admit applies the global and per-IP session ceilings.
func (g *Gateway) admit(ip string) (code int, reason string, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.sessions) >= g.cfg.Security.MaxSessions {
		g.log.Warn("max sessions reached", logger.F("global", len(g.sessions)))
		return 1013, "server busy", false
	}
	perIP := 0
	for _, s := range g.sessions {
		if s.ip == ip {
			perIP++
		}
	}
	if perIP >= g.cfg.Security.MaxSessionsPerIp {
		g.log.Warn("per-ip session limit reached", logger.F("perIp", perIP))
		return 1013, "too many sessions", false
	}
	return 0, "", true
}

func (g *Gateway) track(s *Session) {
	g.mu.Lock()
	g.sessions[s.id] = s
	g.mu.Unlock()
}

func (g *Gateway) untrack(s *Session) {
	g.mu.Lock()
	delete(g.sessions, s.id)
	g.mu.Unlock()
}

func (g *Gateway) sessionCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sessions)
}

// originAllowed enforces the configured allowlist.
func (g *Gateway) originAllowed(origin string) bool {
	allowed := g.cfg.Security.AllowedOrigins
	// Empty means no origin policy configured.
	if len(allowed) == 0 {
		return true
	}

	// Browsers always attach Origin on an upgrade, so an absent header means
	// a non-browser client (the bundled CLI, for example). Those are
	// authenticated by the token, which they can forge anyway.
	if origin == "" {
		return !g.cfg.Security.RequireOrigin
	}

	for _, o := range allowed {
		if o == "*" || o == origin {
			return true
		}
		if normaliseOrigin(o) == normaliseOrigin(origin) {
			return true
		}
	}
	return false
}

// normaliseOrigin reduces an origin to scheme://host, dropping an explicit
// default port so config entries match what browsers actually send.
func normaliseOrigin(o string) string {
	u, err := url.Parse(strings.TrimSpace(o))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return o
	}
	host := u.Host
	switch {
	case u.Scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	case u.Scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	}
	return u.Scheme + "://" + host
}

func isWebSocketUpgrade(r *http.Request) bool {
	if !tokenContains(r.Header.Get("Connection"), "upgrade") {
		return false
	}
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func tokenContains(header, token string) bool {
	for _, t := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(t), token) {
			return true
		}
	}
	return false
}

func offersSubprotocol(header, want string) bool {
	for _, p := range strings.Split(header, ",") {
		if strings.TrimSpace(p) == want {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	if r.RemoteAddr == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Only used for log correlation and session ids.
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
