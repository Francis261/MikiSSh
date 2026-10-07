// Package tlsutil provisions the gateway's TLS material.
//
// The public listener is TLS-only, so a missing certificate is generated
// rather than silently degrading to plaintext.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Francis261/MikiSSh/internal/logger"
)

// GenerateSelfSigned writes a self-signed ECDSA P-256 certificate for
// development. Production deployments should install a certificate from a
// real CA.
//
// It returns absolute paths to the certificate and key.
func GenerateSelfSigned(dir, host string, days int) (certPath, keyPath string, err error) {
	if host == "" {
		host = "localhost"
	}
	if days <= 0 {
		days = 365
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return "", "", fmt.Errorf("create certificate directory: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128) // 128-bit serial
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-5 * time.Minute), // tolerate modest clock skew
		NotAfter:     now.AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	if host == "localhost" {
		tmpl.DNSNames = []string{"localhost"}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("self-sign certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}

	certPath = filepath.Join(abs, "server.crt")
	keyPath = filepath.Join(abs, "server.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// The key is written before the certificate: a half-configured directory
	// must never end up with a certificate whose key is not yet present.
	if err := writeRestrictive(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := writeRestrictive(certPath, certPEM, 0o644); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func writeRestrictive(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile only applies mode on creation; re-assert it so a regenerated
	// key can never be left world-readable.
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// Ensure returns usable certificate and key paths, generating a self-signed
// pair in the certificate's directory when either file is missing.
//
// The paths are absolute, so the caller may safely log them.
func Ensure(certPath, keyPath, host string, log *logger.Logger) (cert, key string, generated bool, err error) {
	certAbs, err := filepath.Abs(certPath)
	if err != nil {
		return "", "", false, err
	}
	keyAbs, err := filepath.Abs(keyPath)
	if err != nil {
		return "", "", false, err
	}

	if fileExists(certAbs) && fileExists(keyAbs) {
		return certAbs, keyAbs, false, nil
	}

	if log != nil {
		log.Warn("TLS material missing — generating a self-signed certificate",
			logger.F("dir", filepath.Dir(certAbs)))
	}

	cert, key, err = GenerateSelfSigned(filepath.Dir(certAbs), host, 365)
	if err != nil {
		return "", "", false, err
	}
	return cert, key, true, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
