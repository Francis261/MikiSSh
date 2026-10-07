// Package config builds the gateway configuration from defaults, an optional
// JSON file, and the environment. Environment variables win, so a deployment
// can inject secrets without ever touching the config file on disk.
package config

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// WSConfig describes the listeners.
type WSConfig struct {
	Host         string       `json:"host"`
	Port         int          `json:"port"`
	Path         string       `json:"path"`
	TLS          TLSConfig    `json:"tls"`
	LoopbackHTTP LoopbackHTTP `json:"loopbackHttp"`
}

// TLSConfig is mandatory on the public listener: there is no plaintext mode.
type TLSConfig struct {
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	MinVersion string `json:"minVersion"`
}

// LoopbackHTTP is an optional second listener speaking plain HTTP for use
// behind a trusted TLS-terminating proxy or Cloudflare Tunnel. TLS is then
// provided by the edge, so the socket never carries plaintext across the
// network. It is hard-restricted to loopback and disabled by default; when
// enabled the tunnel origin URL is http://127.0.0.1:<port><path>.
type LoopbackHTTP struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

// AuthConfig controls token acceptance and handshake throttling.
type AuthConfig struct {
	// Tokens are accepted via Sec-WebSocket-Protocol (preferred, browser
	// safe) or ?token= (CLI convenience).
	Tokens      []string `json:"tokens"`
	MaxAttempts int      `json:"maxAttempts"`
	WindowMs    int64    `json:"windowMs"`
	// Required=false lets clients present no token at all, but only when
	// no tokens are configured either.
	Required bool `json:"required"`
}

// SSHConfig holds the BACKEND credentials. They exist only on the server;
// clients never send a host, port, username, password or key, which removes
// the SSRF and credential-forwarding surface entirely.
type SSHConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	// Auth material is NEVER sent by the client. Leave unset to fall back
	// to the agent or the standard identity files.
	PrivateKey string `json:"privateKey,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	Password   string `json:"password,omitempty"`
	Agent      string `json:"agent,omitempty"`
	// KnownHosts, when set, enforces host-key verification. When empty the
	// gateway accepts whatever key the backend presents, which is the
	// behaviour of the original build and is safe for a loopback target.
	KnownHosts          string `json:"knownHosts,omitempty"`
	KeepaliveIntervalMs int64  `json:"keepaliveIntervalMs"`
	ReadyTimeoutMs      int64  `json:"readyTimeoutMs"`
}

// SecurityConfig is the gateway's request policy.
type Security struct {
	// AllowedOrigins: empty means no origin policy (all origins accepted).
	// Set explicit origins in production to stop a hostile page opening a
	// WebSocket to the gateway on a victim's behalf.
	AllowedOrigins []string `json:"allowedOrigins"`
	// RequireOrigin also rejects requests with no Origin header. Browsers
	// always send one on an upgrade, so absence means a non-browser client
	// such as the bundled CLI; enabling this locks that CLI out.
	RequireOrigin      bool  `json:"requireOrigin"`
	IdleTimeoutMs      int64 `json:"idleTimeoutMs"`
	HandshakeTimeoutMs int64 `json:"handshakeTimeoutMs"`
	MaxSessions        int   `json:"maxSessions"`
	MaxSessionsPerIp   int   `json:"maxSessionsPerIp"`
}

// LogConfig selects the logger threshold.
type LogConfig struct {
	Level string `json:"level"`
}

// Config is the fully resolved gateway configuration.
type Config struct {
	WS       WSConfig   `json:"ws"`
	Auth     AuthConfig `json:"auth"`
	SSH      SSHConfig  `json:"ssh"`
	Security Security   `json:"security"`
	Log      LogConfig  `json:"log"`
	// UI is nil unless explicitly disabled with `"ui": false`.
	UI *bool `json:"ui,omitempty"`
}

// Defaults mirrors the documented baseline configuration.
var Defaults = Config{
	WS: WSConfig{
		Host: "0.0.0.0",
		Port: 8022,
		Path: "/ssh",
		TLS: TLSConfig{
			Cert:       "./certs/server.crt",
			Key:        "./certs/server.key",
			MinVersion: "TLSv1.3",
		},
		LoopbackHTTP: LoopbackHTTP{
			Enabled: false,
			Host:    "127.0.0.1",
			Port:    8023,
		},
	},
	Auth: AuthConfig{
		Tokens:      []string{},
		MaxAttempts: 5,
		WindowMs:    60_000,
		Required:    true,
	},
	SSH: SSHConfig{
		Host:                "127.0.0.1",
		Port:                22,
		Username:            "root",
		KeepaliveIntervalMs: 15_000,
		ReadyTimeoutMs:      20_000,
	},
	Security: Security{
		AllowedOrigins:     []string{},
		RequireOrigin:      false,
		IdleTimeoutMs:      10 * 60_000,
		HandshakeTimeoutMs: 10_000,
		MaxSessions:        32,
		MaxSessionsPerIp:   4,
	},
	Log: LogConfig{Level: "info"},
}

// UIEnabled reports whether the web terminal should be served.
func (c *Config) UIEnabled() bool { return c.UI == nil || *c.UI }

// LoadOptions selects the config file and environment source.
type LoadOptions struct {
	// ConfigPath, when set, must exist. A path taken from the environment
	// is optional, matching the original behaviour of silently ignoring a
	// stale MIKISSH_CONFIG.
	ConfigPath string
	Env        map[string]string
}

// Load merges defaults, an optional JSON file, and environment overrides.
func Load(opts LoadOptions) (*Config, error) {
	env := opts.Env
	if env == nil {
		env = environMap()
	}

	base, err := toMap(Defaults)
	if err != nil {
		return nil, fmt.Errorf("encode defaults: %w", err)
	}

	path := opts.ConfigPath
	explicit := path != ""
	if path == "" {
		path = env["MIKISSH_CONFIG"]
	}
	if path != "" {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(abs)
		switch {
		case err == nil:
			var file map[string]any
			if err := json.Unmarshal(data, &file); err != nil {
				return nil, fmt.Errorf("config file not valid JSON: %s: %w", abs, err)
			}
			base = deepMerge(base, file)
		case os.IsNotExist(err) && !explicit:
			// optional env-supplied path that is not there yet
		case os.IsNotExist(err):
			return nil, fmt.Errorf("config file not found: %s", path)
		default:
			return nil, fmt.Errorf("config file unreadable: %s: %w", path, err)
		}
	}

	merged := deepMerge(base, envOverlay(env))

	raw, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("encode merged config: %w", err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("config does not match the expected shape: %w", err)
	}

	if cfg.WS.Path == "" || !strings.HasPrefix(cfg.WS.Path, "/") {
		cfg.WS.Path = "/" + cfg.WS.Path
	}
	return cfg, nil
}

// envOverlay turns the recognised MIKISSH_* variables into a partial config
// map. Absent variables contribute nothing, which is what makes them lose
// to the file and the defaults.
func envOverlay(env map[string]string) map[string]any {
	ws := map[string]any{}
	tls := map[string]any{}
	loop := map[string]any{}
	authM := map[string]any{}
	ssh := map[string]any{}
	sec := map[string]any{}
	logM := map[string]any{}

	// Presence, not emptiness, decides whether a variable overrides. An
	// absent variable must fall through to the file and the defaults, while
	// a present-but-empty one really does override — matching the original,
	// where only `undefined` lost the merge.
	setStr := func(dst map[string]any, key, envKey string) {
		if v, ok := env[envKey]; ok {
			dst[key] = v
		}
	}
	setNum := func(dst map[string]any, key, envKey string) {
		v, ok := env[envKey]
		if !ok {
			return
		}
		if n, ok := parseNum(v); ok {
			dst[key] = n
		}
	}
	setBool := func(dst map[string]any, key, envKey string) {
		v, ok := env[envKey]
		if !ok {
			return
		}
		if b, ok := parseBool(v); ok {
			dst[key] = b
		}
	}
	setList := func(dst map[string]any, key, envKey string) {
		if v, ok := env[envKey]; ok {
			dst[key] = parseList(v)
		}
	}

	setStr(ws, "host", "MIKISSH_HOST")
	setNum(ws, "port", "MIKISSH_PORT")
	setStr(ws, "path", "MIKISSH_PATH")
	setStr(tls, "cert", "MIKISSH_TLS_CERT")
	setStr(tls, "key", "MIKISSH_TLS_KEY")
	setBool(loop, "enabled", "MIKISSH_LOOPBACK_HTTP")
	setStr(loop, "host", "MIKISSH_LOOPBACK_HOST")
	setNum(loop, "port", "MIKISSH_LOOPBACK_PORT")

	setList(authM, "tokens", "MIKISSH_TOKENS")
	setBool(authM, "required", "MIKISSH_AUTH_REQUIRED")
	setNum(authM, "maxAttempts", "MIKISSH_MAX_ATTEMPTS")
	setNum(authM, "windowMs", "MIKISSH_WINDOW_MS")

	setStr(ssh, "host", "MIKISSH_SSH_HOST")
	setNum(ssh, "port", "MIKISSH_SSH_PORT")
	setStr(ssh, "username", "MIKISSH_SSH_USER")
	setStr(ssh, "privateKey", "MIKISSH_SSH_KEY")
	setStr(ssh, "passphrase", "MIKISSH_SSH_PASSPHRASE")
	setStr(ssh, "password", "MIKISSH_SSH_PASSWORD")
	setStr(ssh, "agent", "MIKISSH_SSH_AGENT")
	setStr(ssh, "knownHosts", "MIKISSH_SSH_KNOWN_HOSTS")

	setList(sec, "allowedOrigins", "MIKISSH_ALLOWED_ORIGINS")
	setBool(sec, "requireOrigin", "MIKISSH_REQUIRE_ORIGIN")
	setNum(sec, "idleTimeoutMs", "MIKISSH_IDLE_TIMEOUT_MS")
	setNum(sec, "maxSessions", "MIKISSH_MAX_SESSIONS")
	setNum(sec, "maxSessionsPerIp", "MIKISSH_MAX_SESSIONS_PER_IP")

	setStr(logM, "level", "MIKISSH_LOG_LEVEL")

	out := map[string]any{}
	if len(tls) > 0 || len(loop) > 0 || len(ws) > 0 {
		if len(tls) > 0 {
			ws["tls"] = tls
		}
		if len(loop) > 0 {
			ws["loopbackHttp"] = loop
		}
		out["ws"] = ws
	}
	if len(authM) > 0 {
		out["auth"] = authM
	}
	if len(ssh) > 0 {
		out["ssh"] = ssh
	}
	if len(sec) > 0 {
		out["security"] = sec
	}
	if len(logM) > 0 {
		out["log"] = logM
	}
	return out
}

// parseBool replicates the original semantics: unset or empty means "no
// opinion", and every value except 0/false/no/off is true.
func parseBool(raw string) (bool, bool) {
	if raw == "" {
		return false, false
	}
	switch strings.ToLower(raw) {
	case "0", "false", "no", "off":
		return false, true
	default:
		return true, true
	}
}

// parseNum mirrors JavaScript's Number(): empty parses as 0, anything that
// is not a finite number is discarded rather than overriding.
func parseNum(raw string) (float64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, true
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

func parseList(raw string) []string {
	out := []string{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// environMap parses the process environment keyed by variable name,
// preserving the distinction between "unset" and "set to empty".
func environMap() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			out[kv[:i]] = kv[i+1:]
		}
	}
	return out
}

func toMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// deepMerge overlays o onto b. Nested objects merge; everything else,
// including arrays, is replaced wholesale.
func deepMerge(b, o map[string]any) map[string]any {
	if len(o) == 0 {
		return b
	}
	out := make(map[string]any, len(b)+len(o))
	for k, v := range b {
		out[k] = v
	}
	for k, v := range o {
		if bv, ok := b[k]; ok {
			bm, bok := bv.(map[string]any)
			om, ook := v.(map[string]any)
			if bok && ook {
				out[k] = deepMerge(bm, om)
				continue
			}
		}
		out[k] = v
	}
	return out
}
