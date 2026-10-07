package auth

import (
	"regexp"
	"testing"
	"time"
)

func TestGenerateTokenIsUniqueAndURLSafe(t *testing.T) {
	a := GenerateToken()
	if b := GenerateToken(); a == b {
		t.Error("two generated tokens were identical")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(a) {
		t.Errorf("token %q is not url-safe", a)
	}
}

func TestSafeEqualHandlesMismatchedLengths(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"abc", "abcd", false},
		{"abc", "abc", true},
		{"", "", true},
	}
	for _, c := range cases {
		if got := SafeEqual(c.a, c.b); got != c.want {
			t.Errorf("SafeEqual(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestExtractTokenPrefersSubprotocolOverQuery(t *testing.T) {
	tok, src := ExtractToken("mikissh, t.SECRET", "")
	if tok != "SECRET" || src != SourceSubprotocol {
		t.Errorf("got (%q, %q), want (SECRET, subprotocol)", tok, src)
	}

	tok, src = ExtractToken("", "token=Q")
	if tok != "Q" || src != SourceQuery {
		t.Errorf("got (%q, %q), want (Q, query)", tok, src)
	}

	// The subprotocol wins even when the query also carries a token.
	tok, src = ExtractToken("mikissh, t.SECRET", "token=Q")
	if tok != "SECRET" || src != SourceSubprotocol {
		t.Errorf("got (%q, %q), want (SECRET, subprotocol)", tok, src)
	}

	tok, _ = ExtractToken("", "/ssh")
	if tok != "" {
		t.Errorf("token = %q, want empty", tok)
	}
}

func TestAuthorizerRejectsRateLimitsAndFailsClosed(t *testing.T) {
	a := New([]string{"good"}, true, 2, time.Minute)

	if v := a.Check("1.2.3.4", "good"); !v.OK {
		t.Errorf("valid token rejected: %v", v.Reason)
	}
	if v := a.Check("1.2.3.4", "bad"); v.OK || v.Reason != "invalid token" {
		t.Errorf("got (%v, %q), want (false, invalid token)", v.OK, v.Reason)
	}
	if v := a.Check("1.2.3.4", "bad"); v.OK || v.Reason != "invalid token" {
		t.Errorf("got (%v, %q), want (false, invalid token)", v.OK, v.Reason)
	}
	// Third failure inside the window: rate limited even for the good token.
	if v := a.Check("1.2.3.4", "good"); v.OK || v.Reason != "rate limited" {
		t.Errorf("got (%v, %q), want (false, rate limited)", v.OK, v.Reason)
	}

	empty := New(nil, true, 5, time.Minute)
	if empty.Configured() {
		t.Error("an authorizer with no tokens must not report configured")
	}
	if v := empty.Check("1.1.1.1", "anything"); v.OK {
		t.Error("an authorizer with no tokens must fail closed")
	}

	optional := New(nil, false, 5, time.Minute)
	if v := optional.Check("1.1.1.1", ""); !v.OK {
		t.Errorf("optional auth rejected an anonymous client: %v", v.Reason)
	}
}
