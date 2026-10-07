// Package bridge connects one gateway session to one SSH connection.
//
// The gateway dials the SSH server using credentials that exist ONLY on the
// server. Clients never supply host, port, username, password or key, which
// removes the SSRF and credential-forwarding surface entirely.
package bridge

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Francis261/MikiSSh/internal/config"
	"github.com/Francis261/MikiSSh/internal/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Algorithm policy: defence in depth, refusing anything but a modern set.
// This is strictly stronger than the library defaults, which still offer
// DH-group14-with-SHA1 and HMAC-SHA1.
var (
	// Post-quantum hybrid first, then the classical options.
	kexAlgorithms = []string{
		ssh.KeyExchangeMLKEM768X25519,
		ssh.KeyExchangeCurve25519,
		ssh.KeyExchangeECDHP256,
		ssh.KeyExchangeECDHP384,
		ssh.KeyExchangeECDHP521,
		ssh.KeyExchangeDH16SHA512,
		ssh.KeyExchangeDH14SHA256,
	}
	cipherAlgorithms = []string{
		ssh.CipherAES256GCM,
		ssh.CipherAES128GCM,
		ssh.CipherChaCha20Poly1305,
		ssh.CipherAES256CTR,
		ssh.CipherAES192CTR,
		ssh.CipherAES128CTR,
	}
	macAlgorithms = []string{
		ssh.HMACSHA256ETM,
		ssh.HMACSHA512ETM,
		ssh.HMACSHA256,
		ssh.HMACSHA512,
	}
	hostKeyAlgorithms = []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoRSASHA512,
		ssh.KeyAlgoRSASHA256,
	}
)

// Options carry the per-session terminal shape. They come from the
// connecting client; everything else about the connection is server-side.
type Options struct {
	Term       string
	Cols       int
	Rows       int
	PrivateKey []byte
}

// Bridge owns exactly one SSH connection.
//
// Set the handlers before calling Connect. Each may be invoked from the
// bridge's goroutines; lifecycle handlers (OnError, OnExit, OnClose) fire at
// most once.
type Bridge struct {
	cfg  *config.SSHConfig
	opts Options
	log  *logger.Logger

	OnReady  func()
	OnError  func(error)
	OnStdout func([]byte)
	OnStderr func([]byte)
	OnExit   func(code int, signal string)
	OnClose  func()

	mu     sync.Mutex
	closed bool
	client *ssh.Client
	sess   *ssh.Session
	stdin  io.WriteCloser
}

// New builds a Bridge. A nil logger is replaced with a discarding one.
func New(cfg *config.SSHConfig, opts Options, log *logger.Logger) *Bridge {
	if opts.Term == "" {
		opts.Term = "xterm-256color"
	}
	if opts.Cols <= 0 {
		opts.Cols = 80
	}
	if opts.Rows <= 0 {
		opts.Rows = 24
	}
	if log == nil {
		log = logger.NewDiscard()
	}
	return &Bridge{cfg: cfg, opts: opts, log: log}
}

// Connect dials and opens a shell in the background. Failures arrive via
// OnError; success via OnReady.
func (b *Bridge) Connect() {
	go b.run()
}

func (b *Bridge) run() {
	client, sess, stdin, stdout, stderr, err := b.establish()
	if err != nil {
		b.fail(err)
		return
	}
	if b.isClosed() {
		b.teardown(sess, client, stdin)
		return
	}

	// From here the session is live, so late failures are reported to the
	// client as a stream error rather than a failed handshake. AUTH_OK is
	// written before the pumps start, so it always precedes shell output
	// on the wire.
	if b.OnReady != nil {
		b.OnReady()
	}
	if b.isClosed() {
		b.teardown(sess, client, stdin)
		return
	}

	go b.pump(stdout, b.OnStdout)
	go b.pump(stderr, b.OnStderr)
	stopKeepalive := b.startKeepalive(client)

	err = sess.Wait()
	stopKeepalive()

	if b.isClosed() {
		// We were torn down from the outside; nothing left to report.
		return
	}

	if code, sig, ok := exitStatus(err); ok {
		if b.OnExit != nil {
			b.OnExit(code, sig)
		}
		// The server reported a status: this is a normal termination. Tear
		// down without firing OnClose, so the gateway leaves the WebSocket
		// open for the client to read the exit frame and hang up itself.
		if b.markClosed() {
			b.teardown(sess, client, stdin)
		}
		return
	}

	b.lost(err)
}

// establish performs the dial, handshake, pty request and shell start.
//
// The output pipes must be taken before Shell(): Session.start() wires up
// stdin/stdout/stderr itself, and asking for a pipe afterwards fails with
// "Stdout already set".
func (b *Bridge) establish() (*ssh.Client, *ssh.Session, io.WriteCloser, io.Reader, io.Reader, error) {
	sshCfg, err := b.clientConfig()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	addr := net.JoinHostPort(b.cfg.Host, fmt.Sprintf("%d", b.cfg.Port))
	readyTimeout := durationMs(b.cfg.ReadyTimeoutMs, 20*time.Second)

	dialer := net.Dialer{Timeout: readyTimeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	// One deadline covering TCP connect and the SSH handshake, cleared
	// afterwards so a long-lived shell is never cut off by it.
	if err := conn.SetDeadline(time.Now().Add(readyTimeout)); err != nil {
		_ = conn.Close()
		return nil, nil, nil, nil, nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshCfg)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("ssh handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	client := ssh.NewClient(c, chans, reqs)
	if !b.register(client, nil, nil) {
		_ = client.Close()
		return nil, nil, nil, nil, nil, errClosed
	}

	sess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("open session: %w", err)
	}
	if !b.register(client, sess, nil) {
		_ = sess.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, errClosed
	}

	// Empty terminal modes: the server's pty defaults apply, which is what
	// the original client sent too.
	if err := sess.RequestPty(b.opts.Term, b.opts.Rows, b.opts.Cols, ssh.TerminalModes{}); err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("request pty: %w", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		_ = sess.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = sess.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if !b.register(client, sess, stdin) {
		_ = stdin.Close()
		_ = sess.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, errClosed
	}

	// Shell() runs Session.start(), which claims the pipes taken above.
	if err := sess.Shell(); err != nil {
		_ = stdin.Close()
		_ = sess.Close()
		_ = client.Close()
		return nil, nil, nil, nil, nil, fmt.Errorf("start shell: %w", err)
	}
	return client, sess, stdin, stdout, stderr, nil
}

// errClosed signals that Close won the race against setup.
var errClosed = errors.New("bridge closed")

// register stores the live handles and reports whether the bridge is still
// open. A false result means the caller must tear down what it just made.
func (b *Bridge) register(c *ssh.Client, s *ssh.Session, w io.WriteCloser) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if c != nil {
		b.client = c
	}
	if s != nil {
		b.sess = s
	}
	if w != nil {
		b.stdin = w
	}
	return !b.closed
}

// clientConfig assembles authentication and the algorithm policy.
func (b *Bridge) clientConfig() (*ssh.ClientConfig, error) {
	var methods []ssh.AuthMethod

	if len(b.opts.PrivateKey) > 0 {
		signer, err := parseSigner(b.opts.PrivateKey, b.cfg.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("load SSH private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if b.cfg.Password != "" {
		methods = append(methods, ssh.Password(b.cfg.Password))
	}
	if b.cfg.Agent != "" {
		signers, err := agentSigners(b.cfg.Agent)
		if err != nil {
			b.log.Warn("ssh agent unavailable", logger.F("err", err.Error()))
		} else if len(signers) > 0 {
			methods = append(methods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
				return signers, nil
			}))
		}
	}
	if len(methods) == 0 {
		return nil, errors.New("no SSH authentication method available " +
			"(set ssh.privateKey, ssh.password or ssh.agent)")
	}

	callback, err := hostKeyCallback(b.cfg.KnownHosts)
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User:              b.cfg.Username,
		Auth:              methods,
		HostKeyCallback:   callback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Config: ssh.Config{
			KeyExchanges: kexAlgorithms,
			Ciphers:      cipherAlgorithms,
			MACs:         macAlgorithms,
		},
	}, nil
}

func parseSigner(key []byte, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
	}
	return ssh.ParsePrivateKey(key)
}

// agentSigners loads identities from an ssh-agent socket.
func agentSigners(socketPath string) ([]ssh.Signer, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return agent.NewClient(conn).Signers()
}

// hostKeyCallback enforces host-key verification when knownHosts is set.
//
// With no path configured the gateway accepts whatever key the backend
// presents. That matches the original build and is the right default for a
// loopback target, where the peer is the same machine; deployments that
// traverse a network should set ssh.knownHosts.
//
// When a path is set, an unknown host is trusted on first use while a
// mismatching known key is a hard failure.
func hostKeyCallback(knownHostsPath string) (ssh.HostKeyCallback, error) {
	if knownHostsPath == "" {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("known_hosts %s: %w", knownHostsPath, err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, remote, key)
		if err == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) && len(ke.Want) == 0 {
			// Nothing recorded for this host yet: trust on first use.
			return nil
		}
		return err
	}, nil
}

// pump forwards SSH output to the session, allocating per chunk so a slow
// consumer never sees a buffer reused under it.
func (b *Bridge) pump(r io.Reader, emit func([]byte)) {
	if r == nil || emit == nil {
		return
	}
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			emit(chunk)
		}
		if err != nil {
			return
		}
	}
}

// startKeepalive sends OpenSSH keepalives so a half-open connection is
// noticed instead of hanging a session forever.
func (b *Bridge) startKeepalive(client *ssh.Client) func() {
	interval := durationMs(b.cfg.KeepaliveIntervalMs, 0)
	if interval <= 0 {
		return func() {}
	}
	stop := make(chan struct{})
	var once sync.Once

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		failures := 0
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				if err == nil {
					failures = 0
					continue
				}
				failures++
				if failures >= 3 {
					b.lost(fmt.Errorf("ssh keepalive failed: %w", err))
					return
				}
			}
		}
	}()

	return func() { once.Do(func() { close(stop) }) }
}

// Write forwards keystrokes to the remote shell.
func (b *Bridge) Write(p []byte) {
	b.mu.Lock()
	stdin, closed := b.stdin, b.closed
	b.mu.Unlock()
	if stdin == nil || closed {
		return
	}
	_, _ = stdin.Write(p)
}

// Resize updates the remote pty size. Best effort: a window-change failure
// must not disturb an otherwise healthy session.
func (b *Bridge) Resize(cols, rows int) {
	b.mu.Lock()
	sess, closed := b.sess, b.closed
	b.mu.Unlock()
	if sess == nil || closed {
		return
	}
	// WindowChange takes (rows, cols).
	_ = sess.WindowChange(rows, cols)
}

// Close tears down the SSH side. It is idempotent and deliberately does not
// fire OnClose: when the gateway initiates the teardown it closes the
// WebSocket itself.
func (b *Bridge) Close() {
	if !b.markClosed() {
		return
	}
	b.mu.Lock()
	sess, client, stdin := b.sess, b.client, b.stdin
	b.mu.Unlock()
	b.teardown(sess, client, stdin)
}

// lost reports an unexpected connection failure and fires OnClose once.
func (b *Bridge) lost(err error) {
	if err != nil && !b.isClosed() && b.OnError != nil {
		b.OnError(err)
	}
	if !b.markClosed() {
		return
	}
	b.mu.Lock()
	sess, client, stdin := b.sess, b.client, b.stdin
	b.mu.Unlock()
	b.teardown(sess, client, stdin)
	if b.OnClose != nil {
		b.OnClose()
	}
}

// fail reports a pre-ready failure, which the gateway turns into a refused
// handshake rather than a stream error.
func (b *Bridge) fail(err error) {
	if err == nil || err == errClosed {
		return
	}
	if b.OnError != nil {
		b.OnError(err)
	}
	b.Close()
}

func (b *Bridge) teardown(sess *ssh.Session, client *ssh.Client, stdin io.WriteCloser) {
	if stdin != nil {
		_ = stdin.Close()
	}
	if sess != nil {
		_ = sess.Close()
	}
	if client != nil {
		_ = client.Close()
	}
}

func (b *Bridge) markClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.closed = true
	return true
}

func (b *Bridge) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// exitStatus translates a Wait result into a shell exit code. ok is false
// when the session died without reporting a status, meaning the connection
// was lost rather than the command finishing.
func exitStatus(err error) (code int, signal string, ok bool) {
	if err == nil {
		return 0, "", true
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), exitErr.Signal(), true
	}
	var missing *ssh.ExitMissingError
	if errors.As(err, &missing) {
		// The server never sent exit-status; treat as a clean end.
		return 0, "", true
	}
	return 0, "", false
}

func durationMs(ms int64, fallback time.Duration) time.Duration {
	if ms <= 0 {
		return fallback
	}
	return time.Duration(ms) * time.Millisecond
}
