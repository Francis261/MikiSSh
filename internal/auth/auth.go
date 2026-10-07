// Package auth implements gateway token authentication.
//
// Tokens arrive over Sec-WebSocket-Protocol (browsers cannot set arbitrary
// headers) or a query string (CLI convenience), are compared in constant
// time, and are rate limited per source IP before any SSH work happens.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SafeEqual compares two strings in constant time for equal lengths.
//
// Length still has to be compared first, so a dummy comparison is performed
// on mismatch to keep the timing profile flat.
func SafeEqual(a, b string) bool {
	ab := []byte(a)
	bb := []byte(b)
	if len(ab) != len(bb) {
		subtle.ConstantTimeCompare(ab, ab)
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

// Fingerprint returns a truncated SHA-256 hex digest of a token. It is what
// audit logs record instead of the token itself.
func Fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:12]
}

// Where a presented token was found.
const (
	SourceSubprotocol = "subprotocol"
	SourceQuery       = "query"
)

// ExtractToken pulls a bearer token out of a WebSocket upgrade request.
//
// Browsers cannot set arbitrary headers, so the primary channel is the
// Sec-WebSocket-Protocol header, which clients send as a subprotocol list:
//
//	["mikissh", "t.<token>"]
//
// `?token=` is supported for CLI clients, but is secondary because query
// strings frequently end up in access logs. Both return values are empty
// when no token is present.
func ExtractToken(header, rawQuery string) (token, source string) {
	if header != "" {
		for _, p := range strings.Split(header, ",") {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "t.") {
				return p[2:], SourceSubprotocol
			}
			// tolerate a raw bearer form
			if len(p) >= 7 && strings.EqualFold(p[:7], "bearer.") {
				return p[7:], SourceSubprotocol
			}
		}
	}

	if rawQuery != "" {
		if q, err := url.ParseQuery(rawQuery); err == nil {
			if v := q.Get("token"); v != "" {
				return v, SourceQuery
			}
		}
	}
	return "", ""
}

// Verdict is the outcome of a handshake check.
type Verdict struct {
	OK     bool
	Reason string
}

func allow() Verdict { return Verdict{OK: true} }

func deny(reason string) Verdict { return Verdict{Reason: reason} }

// Authorizer verifies tokens with per-IP sliding-window rate limiting.
// It rejects handshakes before any SSH connection is attempted.
//
// The zero value is not usable; call New.
type Authorizer struct {
	mu          sync.Mutex
	required    bool
	maxAttempts int
	window      time.Duration
	buckets     map[string][]time.Time
	tokens      []string
	hashed      []string
}

// New builds an Authorizer. Empty tokens are dropped, and each token is
// pre-hashed so raw secrets never sit in a structure that gets logged.
func New(tokens []string, required bool, maxAttempts int, window time.Duration) *Authorizer {
	a := &Authorizer{
		required:    required,
		maxAttempts: maxAttempts,
		window:      window,
		buckets:     make(map[string][]time.Time),
	}
	for _, t := range tokens {
		if t == "" {
			continue
		}
		a.tokens = append(a.tokens, t)
		a.hashed = append(a.hashed, Fingerprint(t))
	}
	return a
}

// Configured reports whether at least one token is provisioned.
func (a *Authorizer) Configured() bool { return len(a.tokens) > 0 }

// Fingerprints returns the audit fingerprints of the configured tokens.
// The raw tokens are never exposed through this accessor.
func (a *Authorizer) Fingerprints() []string {
	out := make([]string, len(a.hashed))
	copy(out, a.hashed)
	return out
}

// Check validates a presented token for ip.
func (a *Authorizer) Check(ip, presented string) Verdict {
	// Auth optional and nothing provisioned: open by design.
	if !a.required && !a.Configured() {
		return allow()
	}

	// Auth is required but no tokens were provisioned: fail closed.
	if !a.Configured() {
		return deny("no tokens configured")
	}

	if presented == "" {
		return deny("missing token")
	}

	a.mu.Lock()
	limited := a.rateLimitedLocked(ip)
	a.mu.Unlock()
	if limited {
		return deny("rate limited")
	}

	// Compare against every token rather than stopping at the first match,
	// so the work performed does not reveal which entry matched.
	match := false
	for _, t := range a.tokens {
		if SafeEqual(t, presented) {
			match = true
		}
	}

	if match {
		a.clear(ip)
		return allow()
	}

	a.mu.Lock()
	a.recordLocked(ip)
	a.mu.Unlock()
	return deny("invalid token")
}

// rateLimitedLocked reports whether ip has exhausted its attempt budget,
// pruning stale entries as a side effect.
func (a *Authorizer) rateLimitedLocked(ip string) bool {
	live := a.pruneLocked(ip)
	return len(live) >= a.maxAttempts
}

func (a *Authorizer) recordLocked(ip string) {
	now := time.Now()
	live := a.pruneLocked(ip)
	a.buckets[ip] = append(live, now)
}

func (a *Authorizer) clear(ip string) {
	a.mu.Lock()
	delete(a.buckets, ip)
	a.mu.Unlock()
}

func (a *Authorizer) pruneLocked(ip string) []time.Time {
	arr := a.buckets[ip]
	now := time.Now()
	live := make([]time.Time, 0, len(arr))
	for _, t := range arr {
		if now.Sub(t) < a.window {
			live = append(live, t)
		}
	}
	a.buckets[ip] = live
	return live
}

// Sweep drops stale buckets so memory stays bounded on long-running daemons.
func (a *Authorizer) Sweep() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for ip, arr := range a.buckets {
		live := make([]time.Time, 0, len(arr))
		for _, t := range arr {
			if now.Sub(t) < a.window {
				live = append(live, t)
			}
		}
		if len(live) == 0 {
			delete(a.buckets, ip)
		} else {
			a.buckets[ip] = live
		}
	}
}

// GenerateToken returns a cryptographically random 256-bit url-safe token.
func GenerateToken() string {
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		panic("mikissh: no system entropy: " + err.Error())
	}
	return base64RawURL(b)
}
