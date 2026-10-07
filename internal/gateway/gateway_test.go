package gateway_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Francis261/MikiSSh/internal/config"
	"github.com/Francis261/MikiSSh/internal/gateway"
	"github.com/Francis261/MikiSSh/internal/logger"
	"github.com/Francis261/MikiSSh/internal/protocol"
	"github.com/coder/websocket"
)

// The dev certificate is self-signed, and redirects are never followed so a
// 301 cannot mask what the server actually replied.
var testClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var tokenSeq atomic.Int64

// nextToken gives each suite its own token, so rate-limiting state recorded
// by one test cannot bleed into the next.
func nextToken() string { return fmt.Sprintf("testtoken%d", tokenSeq.Add(1)) }

func getPort(t testing.TB) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// tmpKey provisions a throwaway key when the real one is absent, so the
// suite runs on a clean checkout without ever opening an SSH connection.
func tmpKey(t *testing.T) string {
	t.Helper()
	rel := "./.ssh/id_ed25519"
	if _, err := os.Stat(config.ResolveAgainst(config.FindRoot(), rel)); err == nil {
		return rel
	}
	f := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(f, []byte("# placeholder key for tests\n"), 0o600); err != nil {
		t.Fatalf("write placeholder key: %v", err)
	}
	return f
}

// build loads a config from an explicit environment and constructs a
// gateway without binding a socket. Passing MIKISSH_PORT in env reserves
// the port up front, which callers need when the config must reference it.
func build(t *testing.T, token string, env map[string]string) (*gateway.Gateway, *config.Config) {
	t.Helper()
	full := map[string]string{
		"MIKISSH_HOST":      "127.0.0.1",
		"MIKISSH_TOKENS":    token,
		"MIKISSH_LOG_LEVEL": "silent",
		"MIKISSH_SSH_KEY":   tmpKey(t),
	}
	if _, ok := env["MIKISSH_PORT"]; !ok {
		full["MIKISSH_PORT"] = strconv.Itoa(getPort(t))
	}
	for k, v := range env {
		full[k] = v
	}

	cfg, err := config.Load(config.LoadOptions{Env: full})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	gw, err := gateway.New(cfg, logger.NewDiscard())
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	return gw, cfg
}

// startGateway binds the listeners and stops them when the test ends.
func startGateway(t *testing.T, gw *gateway.Gateway) int {
	t.Helper()
	addr, err := gw.Start()
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Stop() })
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address type %T", addr)
	}
	return tcp.Port
}

// result is the outcome of one connection attempt.
type result struct {
	ok   bool
	code int
	body string
	http int
	err  string
}

func (r result) String() string {
	switch {
	case r.ok:
		return "connected"
	case r.http > 0:
		return fmt.Sprintf("HTTP %d: %s", r.http, strings.TrimSpace(r.body))
	case r.code != 0:
		return fmt.Sprintf("closed with %d", r.code)
	default:
		return fmt.Sprintf("error: %s", r.err)
	}
}

// attempt resolves once the outcome is known: a KEX greeting means the
// handshake succeeded, a close or a rejected upgrade means it did not.
// Resolving on "connected" would race the server's rejection frame.
func attempt(port int, scheme, path, tok, origin string) result {
	protocols := []string{"mikissh"}
	if tok != "" {
		protocols = append(protocols, "t."+tok)
	}
	hdr := http.Header{}
	if origin != "" {
		hdr.Set("Origin", origin)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	conn, resp, err := websocket.Dial(ctx,
		fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, port, path),
		&websocket.DialOptions{
			Subprotocols: protocols,
			HTTPHeader:   hdr,
			HTTPClient:   testClient,
		})
	if err != nil {
		if resp != nil && resp.StatusCode > 0 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return result{http: resp.StatusCode, body: string(body)}
		}
		return result{err: err.Error()}
	}
	defer conn.CloseNow()

	for {
		_, data, rerr := conn.Read(ctx)
		if rerr != nil {
			if code := websocket.CloseStatus(rerr); code >= 0 {
				return result{code: int(code)}
			}
			return result{err: rerr.Error()}
		}
		msg, derr := protocol.Decode(data)
		if derr != nil {
			continue
		}
		if msg.Type == protocol.TypeKex {
			return result{ok: true}
		}
	}
}

// page is one static HTTP response.
type page struct {
	status int
	header http.Header
	body   string
}

// get fetches a static asset over scheme://127.0.0.1:port.
//
// The request target is set verbatim: path normalisation would hide exactly
// the traversal this exists to exercise.
func get(t *testing.T, scheme string, port int, rawPath string) page {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://example.invalid/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	host := fmt.Sprintf("127.0.0.1:%d", port)
	req.URL = &url.URL{Scheme: scheme, Host: host, Path: rawPath, RawPath: rawPath}

	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s://%s%s: %v", scheme, host, rawPath, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return page{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

// ---------------------------------------------------------------- suite 1

func TestGatewaySecurity(t *testing.T) {
	token := nextToken()
	// The allowlist has to reference the listener's port, so reserve it
	// before the config is loaded.
	free := getPort(t)
	gw, _ := build(t, token, map[string]string{
		"MIKISSH_PORT":            strconv.Itoa(free),
		"MIKISSH_ALLOWED_ORIGINS": fmt.Sprintf("https://gw.example,https://127.0.0.1:%d", free),
		"MIKISSH_MAX_ATTEMPTS":    "3",
	})
	port := startGateway(t, gw)
	origin := fmt.Sprintf("https://127.0.0.1:%d", port)

	t.Run("rejects a missing token", func(t *testing.T) {
		r := attempt(port, "wss", "/ssh", "", origin)
		if r.ok || r.code != 1008 {
			t.Errorf("got %v, want a close with 1008", r)
		}
	})

	t.Run("rejects an invalid token", func(t *testing.T) {
		r := attempt(port, "wss", "/ssh", "wrong-token", origin)
		if r.ok || r.code != 1008 {
			t.Errorf("got %v, want a close with 1008", r)
		}
	})

	t.Run("rejects a disallowed origin", func(t *testing.T) {
		r := attempt(port, "wss", "/ssh", token, "https://evil.example")
		if r.ok || r.code != 1008 {
			t.Errorf("got %v, want a close with 1008", r)
		}
	})

	t.Run("allows a non-browser client that omits Origin", func(t *testing.T) {
		// The bundled CLI sends no Origin header; an origin policy must
		// not lock it out, since the token is what authenticates it.
		r := attempt(port, "wss", "/ssh", token, "")
		if !r.ok {
			t.Errorf("CLI-style handshake must be accepted, got %v", r)
		}
	})

	t.Run("rejects plaintext ws:// (no TLS)", func(t *testing.T) {
		r := attempt(port, "ws", "/ssh", "", "")
		if r.ok {
			t.Error("plaintext upgrade must fail")
		}
	})

	t.Run("serves the UI with a strict CSP", func(t *testing.T) {
		p := get(t, "https", port, "/")
		if p.status != 200 {
			t.Fatalf("status = %d, want 200", p.status)
		}
		csp := p.header.Get("Content-Security-Policy")
		if csp == "" {
			t.Fatal("CSP header missing")
		}
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("CSP lacks frame-ancestors 'none': %s", csp)
		}
		if !strings.Contains(csp, "default-src 'self'") {
			t.Errorf("CSP lacks default-src 'self': %s", csp)
		}
		if p.header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("nosniff header = %q", p.header.Get("X-Content-Type-Options"))
		}
		if !strings.Contains(p.body, "MIKISSH") {
			t.Error("index.html does not mention MIKISSH")
		}
	})

	t.Run("serves vendored xterm without a CDN", func(t *testing.T) {
		js := get(t, "https", port, "/vendor/xterm.js")
		if js.status != 200 {
			t.Errorf("/vendor/xterm.js status = %d, want 200", js.status)
		}
		if !strings.Contains(js.header.Get("Content-Type"), "javascript") {
			t.Errorf("xterm.js content-type = %q", js.header.Get("Content-Type"))
		}
		css := get(t, "https", port, "/vendor/xterm.css")
		if css.status != 200 {
			t.Errorf("/vendor/xterm.css status = %d, want 200", css.status)
		}
		if !strings.Contains(css.header.Get("Content-Type"), "css") {
			t.Errorf("xterm.css content-type = %q", css.header.Get("Content-Type"))
		}
		// The page must not pull any resource from a third-party origin.
		re := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']https?://`)
		if re.MatchString(get(t, "https", port, "/").body) {
			t.Error("page references an external resource")
		}
	})

	t.Run("blocks path traversal", func(t *testing.T) {
		paths := []string{
			"/../package.json",
			"/..%2fpackage.json",
			"/%2e%2e/%2e%2e/etc/passwd",
		}
		for _, p := range paths {
			page := get(t, "https", port, p)
			switch page.status {
			case 403, 404, 200:
				// acceptable
			default:
				t.Errorf("%s -> %d, want 403/404/200", p, page.status)
				continue
			}
			if page.status == 200 {
				if strings.Contains(page.body, `"ssh2"`) {
					t.Errorf("traversal leaked package.json via %s", p)
				}
				if strings.Contains(page.body, "root:x:") {
					t.Errorf("traversal leaked /etc/passwd via %s", p)
				}
			}
		}
	})

	t.Run("rejects unknown message types without crashing", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, resp, err := websocket.Dial(ctx,
			fmt.Sprintf("wss://127.0.0.1:%d/ssh", port),
			&websocket.DialOptions{
				Subprotocols: []string{"mikissh", "t." + token},
				HTTPHeader:   http.Header{"Origin": []string{origin}},
				HTTPClient:   testClient,
			})
		if err != nil {
			if resp != nil {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				t.Fatalf("dial: %v (HTTP %d: %s)", err, resp.StatusCode, body)
			}
			t.Fatalf("dial: %v", err)
		}
		defer conn.CloseNow()

		var got []protocol.Type
		for range 8 {
			_, data, rerr := conn.Read(ctx)
			if rerr != nil {
				t.Fatalf("read: %v", rerr)
			}
			msg, derr := protocol.Decode(data)
			if derr != nil {
				continue
			}
			got = append(got, msg.Type)
			if msg.Type == protocol.TypeKex {
				frame, _ := protocol.Encode(protocol.Type(0x7e), make([]byte, 4))
				if werr := conn.Write(ctx, websocket.MessageBinary, frame); werr != nil {
					t.Fatalf("write: %v", werr)
				}
			}
			if msg.Type == protocol.TypeError {
				break
			}
		}
		if !slices.Contains(got, protocol.TypeKex) {
			t.Error("server should greet first")
		}
		if !slices.Contains(got, protocol.TypeError) {
			t.Errorf("unknown type did not produce an error frame; got %v", got)
		}
	})
}

// ---------------------------------------------------------------- suite 2

func TestLoopbackPlainHTTPListener(t *testing.T) {
	token := nextToken()
	plainPort := getPort(t)
	gw, _ := build(t, token, map[string]string{
		"MIKISSH_LOOPBACK_HTTP": "true",
		"MIKISSH_LOOPBACK_PORT": strconv.Itoa(plainPort),
	})
	tlsPort := startGateway(t, gw)

	t.Run("accepts a plain ws:// handshake with a valid token", func(t *testing.T) {
		r := attempt(plainPort, "ws", "/ssh", token, "")
		if !r.ok {
			t.Errorf("expected success, got %v", r)
		}
	})

	t.Run("still rejects a bad token on the plain listener", func(t *testing.T) {
		r := attempt(plainPort, "ws", "/ssh", "nope", "")
		if r.ok || r.code != 1008 {
			t.Errorf("got %v, want a close with 1008", r)
		}
	})

	t.Run("the TLS listener keeps working alongside it", func(t *testing.T) {
		r := attempt(tlsPort, "wss", "/ssh", token, "")
		if !r.ok {
			t.Errorf("expected success, got %v", r)
		}
	})

	t.Run("TLS listener still refuses plain ws://", func(t *testing.T) {
		if r := attempt(tlsPort, "ws", "/ssh", token, ""); r.ok {
			t.Errorf("expected failure, got %v", r)
		}
	})

	// The reply must be a fully-formed 404. Truncating it makes any proxy
	// in front report 502 instead.
	t.Run("rejects an upgrade on the wrong path", func(t *testing.T) {
		r := attempt(plainPort, "ws", "/admin", token, "")
		if r.ok {
			t.Fatal("upgrade on an unexpected path must not be accepted")
		}
		if r.http != 404 {
			t.Errorf("got %v, want 404", r)
		}
		if !strings.Contains(r.body, "/ssh") {
			t.Errorf("error should point at the real endpoint; body = %q", r.body)
		}
	})

	t.Run("rejects an upgrade at the site root the same way", func(t *testing.T) {
		r := attempt(plainPort, "ws", "/", token, "")
		if r.ok {
			t.Fatal("upgrade at the site root must not be accepted")
		}
		if r.http != 404 {
			t.Errorf("got %v, want 404", r)
		}
		if !strings.Contains(r.body, "/ssh") {
			t.Errorf("error should point at the real endpoint; body = %q", r.body)
		}
	})

	t.Run("still serves the web UI on both listeners", func(t *testing.T) {
		a := get(t, "https", tlsPort, "/")
		if a.status != 200 {
			t.Errorf("TLS listener status = %d, want 200", a.status)
		}
		b := get(t, "http", plainPort, "/")
		if b.status != 200 {
			t.Errorf("plain listener status = %d, want 200", b.status)
		}
		if b.header.Get("Content-Security-Policy") == "" {
			t.Error("CSP applies on the plain listener too")
		}
	})
}

// ---------------------------------------------------------------- suite 3

func TestLoopbackBindingIsEnforced(t *testing.T) {
	t.Run("refuses a non-loopback bind address", func(t *testing.T) {
		gw, _ := build(t, nextToken(), map[string]string{
			"MIKISSH_LOOPBACK_HTTP": "true",
			"MIKISSH_LOOPBACK_HOST": "0.0.0.0",
			"MIKISSH_LOOPBACK_PORT": strconv.Itoa(getPort(t)),
		})
		_, err := gw.Start()
		if err == nil {
			t.Fatal("exposing the plain listener publicly must be impossible")
		}
		if !strings.Contains(err.Error(), "must be a loopback address") {
			t.Errorf("error = %q, want it to mention the loopback rule", err)
		}
		// Release any resources the rejected start may have touched.
		_ = gw.Stop()
	})

	t.Run("is disabled by default", func(t *testing.T) {
		token := nextToken()
		gw, cfg := build(t, token, nil)
		if cfg.WS.LoopbackHTTP.Enabled {
			t.Fatal("loopback listener must be off unless explicitly enabled")
		}
		port := startGateway(t, gw)
		if r := attempt(port, "ws", "/ssh", token, ""); r.ok {
			t.Errorf("plain ws must not reach the default gateway, got %v", r)
		}
	})
}
