package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// IDENTITY_FALLBACKS are the standard OpenSSH identity filenames probed when
// no key is configured.
var IDENTITY_FALLBACKS = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

// ResolvePrivateKey returns the key material used to reach the backend SSH
// server, or nil when the deployment relies on the agent or a password.
//
// An explicitly configured path that does not exist is a hard error: a typo
// must not silently degrade into password or agent authentication.
func ResolvePrivateKey(cfg *Config) ([]byte, error) {
	if cfg.SSH.PrivateKey != "" {
		abs, err := filepath.Abs(cfg.SSH.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("SSH private key not found: %s", cfg.SSH.PrivateKey)
		}
		b, err := os.ReadFile(abs)
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("SSH private key not found: %s", abs)
		}
		if err != nil {
			return nil, fmt.Errorf("SSH private key unreadable: %s: %w", abs, err)
		}
		return b, nil
	}

	if cfg.SSH.Password != "" || cfg.SSH.Agent != "" {
		return nil, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}
	sshDir := filepath.Join(home, ".ssh")
	for _, name := range IDENTITY_FALLBACKS {
		if b, err := os.ReadFile(filepath.Join(sshDir, name)); err == nil {
			return b, nil
		}
	}
	return nil, nil
}

// AssertLoopback refuses a non-loopback bind for the plain listener.
// Exposing it publicly would put an unauthenticated, unencrypted socket on
// the network, so this is enforced in code rather than by documentation.
func AssertLoopback(host string) error {
	h := strings.TrimSpace(host)
	if h == "localhost" || h == "::1" || h == "0:0:0:0:0:0:0:1" {
		return nil
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf(
		"ws.loopbackHttp.host must be a loopback address (got %q). "+
			"Expose the service through a reverse proxy or tunnel instead.", host)
}

// LoopbackAddr renders the tunnel origin URL for the plain listener.
func (c *Config) LoopbackAddr() string {
	return fmt.Sprintf("%s:%d", c.WS.LoopbackHTTP.Host, c.WS.LoopbackHTTP.Port)
}
