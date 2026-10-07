package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestEnvOverridesDefaults(t *testing.T) {
	cfg, err := Load(LoadOptions{Env: map[string]string{
		"MIKISSH_PORT":            "9999",
		"MIKISSH_ALLOWED_ORIGINS": "https://a.example,https://b.example",
		"MIKISSH_SSH_PORT":        "2222",
	}})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.WS.Port != 9999 {
		t.Errorf("ws.port = %d, want 9999", cfg.WS.Port)
	}
	if want := []string{"https://a.example", "https://b.example"}; !reflect.DeepEqual(cfg.Security.AllowedOrigins, want) {
		t.Errorf("allowedOrigins = %v, want %v", cfg.Security.AllowedOrigins, want)
	}
	if cfg.SSH.Port != 2222 {
		t.Errorf("ssh.port = %d, want 2222", cfg.SSH.Port)
	}
	if cfg.WS.TLS.MinVersion != "TLSv1.3" {
		t.Errorf("tls.minVersion = %q, want TLSv1.3", cfg.WS.TLS.MinVersion)
	}
}

func TestNormalisesPathPrefix(t *testing.T) {
	cfg, err := Load(LoadOptions{Env: map[string]string{"MIKISSH_PATH": "shell"}})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.WS.Path != "/shell" {
		t.Errorf("ws.path = %q, want /shell", cfg.WS.Path)
	}
}

// An absent variable must not override, while a present-but-empty one must
// (the original only lost the merge to `undefined`).
func TestAbsentEnvLosesButEmptyEnvWins(t *testing.T) {
	absent, err := Load(LoadOptions{Env: map[string]string{}})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if absent.WS.Host != Defaults.WS.Host {
		t.Errorf("ws.host = %q, want default %q", absent.WS.Host, Defaults.WS.Host)
	}

	empty, err := Load(LoadOptions{Env: map[string]string{"MIKISSH_HOST": ""}})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if empty.WS.Host != "" {
		t.Errorf("ws.host = %q, want empty override to win", empty.WS.Host)
	}
}

func TestUIEnabledUnlessExplicitlyDisabled(t *testing.T) {
	cfg, err := Load(LoadOptions{Env: map[string]string{}})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.UIEnabled() {
		t.Error("ui should default to enabled")
	}
	off := false
	cfg.UI = &off
	if cfg.UIEnabled() {
		t.Error(`"ui": false should disable the web terminal`)
	}
}

func TestAssertLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1", "localhost", "::1", "127.0.0.5"} {
		if err := AssertLoopback(ok); err != nil {
			t.Errorf("AssertLoopback(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0", "192.168.1.10", "example.com", ""} {
		err := AssertLoopback(bad)
		if err == nil {
			t.Errorf("AssertLoopback(%q) = nil, want an error", bad)
			continue
		}
		if !strings.Contains(err.Error(), "must be a loopback address") {
			t.Errorf("AssertLoopback(%q) = %q, want it to mention the loopback rule", bad, err)
		}
	}
}
