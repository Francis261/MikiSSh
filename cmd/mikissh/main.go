// Command mikissh is the MikiSSh gateway and terminal client.
//
//	mikissh server   [--config <file>] [--port N] [--host H]
//	mikissh client   --url wss://host/ssh --token T [--insecure]
//	mikissh gen-cert [--out <dir>] [--days N] [--host <name>]
//	mikissh gen-token
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"

	"github.com/Francis261/MikiSSh/internal/auth"
	"github.com/Francis261/MikiSSh/internal/client"
	"github.com/Francis261/MikiSSh/internal/config"
	"github.com/Francis261/MikiSSh/internal/gateway"
	"github.com/Francis261/MikiSSh/internal/logger"
	"github.com/Francis261/MikiSSh/internal/tlsutil"
)

// usage is a var, not a const: Go constant expressions cannot slice.
var usage = `
MikiSSh — secure SSH over WebSocket

Usage:
  mikissh server   [--config <file>] [--port N] [--host H]
  mikissh client   --url wss://host/ssh --token T [--insecure]
  mikissh gen-cert [--out <dir>] [--days N] [--host <name>]
  mikissh gen-token
  mikissh help

Environment:
  MIKISSH_CONFIG, MIKISSH_PORT, MIKISSH_TOKENS, MIKISSH_SSH_HOST,
  MIKISSH_SSH_PORT, MIKISSH_SSH_USER, MIKISSH_SSH_KEY,
  MIKISSH_TLS_CERT, MIKISSH_TLS_KEY, MIKISSH_ALLOWED_ORIGINS,
  MIKISSH_LOG_LEVEL
`[1:]

func main() {
	var err error

	args := os.Args[1:]
	command := ""
	if len(args) > 0 {
		command, args = args[0], args[1:]
	}

	switch command {
	case "server":
		err = runServer(args)
	case "client":
		err = runClient(args)
	case "gen-cert":
		err = runGenCert(args)
	case "gen-token":
		err = runGenToken(args)
	case "help", "--help", "-h", "":
		fmt.Println(usage)
	case "version", "--version":
		fmt.Println(gateway.Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", command)
		fmt.Println(usage)
		os.Exit(2)
	}

	if err != nil {
		// User-facing failures print one line, not a stack trace.
		fmt.Fprintf(os.Stderr, "mikissh: %s\n", err.Error())
		if os.Getenv("MIKISSH_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "%s\n", debug.Stack())
		}
		os.Exit(exitCode(err))
	}
}

// exitCode preserves the client's documented codes; everything else is a
// plain failure.
func exitCode(err error) int {
	var f *client.Failure
	if errors.As(err, &f) {
		return f.Code
	}
	return 1
}

// ------------------------------------------------------------------ server

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "path to the JSON configuration file")
	port := fs.String("port", "", "override the TLS listener port")
	host := fs.String("host", "", "override the TLS listener address")
	logLevel := fs.String("log-level", "", "override the log level")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Command line overrides become environment overrides, exactly as the
	// original did, so precedence stays: flags > env > file > defaults.
	if *port != "" {
		_ = os.Setenv("MIKISSH_PORT", *port)
	}
	if *host != "" {
		_ = os.Setenv("MIKISSH_HOST", *host)
	}
	if *logLevel != "" {
		_ = os.Setenv("MIKISSH_LOG_LEVEL", *logLevel)
	}

	cfg, err := config.Load(config.LoadOptions{ConfigPath: *configPath})
	if err != nil {
		return err
	}
	log := logger.New(cfg.Log.Level, os.Stdout)

	gw, err := gateway.New(cfg, log)
	if err != nil {
		return err
	}
	if _, err := gw.Start(); err != nil {
		return err
	}

	// A daemon must exit non-zero so the supervisor restarts it, and should
	// log the cause structurally instead of dumping a raw stack.
	defer func() {
		if r := recover(); r != nil {
			log.Error("panic",
				logger.F("reason", fmt.Sprintf("%v", r)),
				logger.F("stack", string(debug.Stack())))
			os.Exit(1)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	log.Info("shutting down", logger.F("sig", sig.String()))
	if err := gw.Stop(); err != nil {
		log.Error("shutdown error", logger.F("err", err.Error()))
	}
	return nil
}

// ------------------------------------------------------------------ client

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	rawURL := fs.String("url", "", "gateway URL, e.g. wss://host/ssh")
	rawURLShort := fs.String("u", "", "shorthand for --url")
	token := fs.String("token", "", "access token (defaults to MIKISSH_TOKEN)")
	tokenShort := fs.String("t", "", "shorthand for --token")
	insecure := fs.Bool("insecure", false, "allow ws:// and skip certificate verification")
	termName := fs.String("term", "", "terminal type to request")
	if err := fs.Parse(args); err != nil {
		return err
	}

	target := *rawURL
	if target == "" {
		target = *rawURLShort
	}
	tok := *token
	if tok == "" {
		tok = *tokenShort
	}
	if tok == "" {
		tok = os.Getenv("MIKISSH_TOKEN")
	}

	return client.Run(client.Options{
		URL:      target,
		Token:    tok,
		Insecure: *insecure,
		Term:     *termName,
	})
}

// ---------------------------------------------------------------- gen-token

func runGenToken(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("gen-token takes no arguments")
	}
	token := auth.GenerateToken()
	fmt.Println(token)
	fmt.Fprintf(os.Stderr,
		"\nAdd to your config:\n  \"auth\": { \"tokens\": [\"%s\"] }\n"+
			"or export MIKISSH_TOKENS=\"%s\"\n", token, token)
	return nil
}

// ---------------------------------------------------------------- gen-cert

func runGenCert(args []string) error {
	fs := flag.NewFlagSet("gen-cert", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", "./certs", "output directory")
	days := fs.Int("days", 365, "validity in days")
	host := fs.String("host", "localhost", "certificate common name")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Relative paths land in the project directory, so manage.sh's check
	// for certs/server.crt matches whatever this command writes.
	dir := config.ResolveAgainst(config.FindRoot(), *out)
	if fileExists(filepath.Join(dir, "server.key")) && fileExists(filepath.Join(dir, "server.crt")) {
		return fmt.Errorf("certs already exist in %s (delete them to regenerate)", dir)
	}

	cert, key, err := tlsutil.GenerateSelfSigned(dir, *host, *days)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", cert)
	fmt.Printf("wrote %s\n", key)
	fmt.Fprintln(os.Stderr, "\nFor production, prefer a certificate from a real CA.")
	return nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
