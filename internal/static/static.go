// Package static serves the web terminal and its local vendor assets.
//
// Everything the page loads ships with the binary's own files: there is no
// CDN and no runtime dependency on node_modules, so a host reset cannot
// break the UI.
package static

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var securityHeaders = map[string]string{
	"X-Content-Type-Options":       "nosniff",
	"X-Frame-Options":              "DENY",
	"Referrer-Policy":              "no-referrer",
	"Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
}

// CSP mirrors the original policy: no third-party origins, no framing, no
// base-tag injection.
const CSP = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"connect-src 'self' wss: ws:; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// Handler serves files out of root, with traversal confined to that
// directory.
type Handler struct {
	root    string
	enabled bool
}

// New builds a Handler rooted at root. When enabled is false every request
// gets a 404, which is how the UI is switched off entirely.
func New(root string, enabled bool) (*Handler, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Handler{root: abs, enabled: enabled}, nil
}

// Root reports the directory being served.
func (h *Handler) Root() string { return h.root }

var extensionTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".json":  "application/json; charset=utf-8",
	".map":   "application/json; charset=utf-8",
	".svg":   "image/svg+xml",
	".ico":   "image/x-icon",
	".woff2": "font/woff2",
}

func contentType(path string) string {
	if t, ok := extensionTypes[strings.ToLower(filepath.Ext(path))]; ok {
		return t
	}
	if t := mime.TypeByExtension(filepath.Ext(path)); t != "" {
		return t
	}
	return "application/octet-stream"
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		plain(w, http.StatusMethodNotAllowed, "method not allowed", map[string]string{
			"Allow": "GET, HEAD",
		})
		return
	}
	if !h.enabled {
		plain(w, http.StatusNotFound, "not found", nil)
		return
	}

	p := r.URL.Path
	if p == "" {
		p = "/"
	}

	if p == "/" || p == "/index.html" {
		h.serveFile(w, r, filepath.Join(h.root, "index.html"))
		return
	}

	target := filepath.Join(h.root, p)
	// filepath.Join cleans the result, so an escaping path lands outside
	// root and fails this prefix test rather than being opened.
	if !strings.HasPrefix(target, h.root+string(os.PathSeparator)) {
		plain(w, http.StatusForbidden, "forbidden", nil)
		return
	}

	st, err := os.Stat(target)
	if err != nil {
		plain(w, http.StatusNotFound, "not found", nil)
		return
	}
	if st.IsDir() {
		plain(w, http.StatusNotFound, "not found", nil)
		return
	}
	h.serveFile(w, r, target)
}

func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, target string) {
	st, err := os.Stat(target)
	if err != nil {
		plain(w, http.StatusNotFound, "not found", nil)
		return
	}

	etag := fmt.Sprintf("W/%q", strconv.FormatInt(st.Size(), 10)+"-"+strconv.FormatInt(st.ModTime().UnixMilli(), 10))
	hdr := header(true)
	hdr.Set("ETag", etag)

	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		applyHeaders(w.Header(), hdr)
		return
	}

	f, err := os.Open(target)
	if err != nil {
		plain(w, http.StatusNotFound, "not found", nil)
		return
	}
	defer f.Close()

	hdr.Set("Content-Type", contentType(target))
	hdr.Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	hdr.Set("Cache-Control", "no-cache")
	applyHeaders(w.Header(), hdr)
	w.WriteHeader(http.StatusOK)

	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, f)
}

func header(withCSP bool) http.Header {
	h := make(http.Header, len(securityHeaders)+1)
	for k, v := range securityHeaders {
		h.Set(k, v)
	}
	if withCSP {
		h.Set("Content-Security-Policy", CSP)
	}
	return h
}

func applyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Set(k, v)
		}
	}
}

// plain writes a text response carrying the standard hardening headers.
// CSP is deliberately omitted for errors, matching the original.
func plain(w http.ResponseWriter, code int, body string, extra map[string]string) {
	hdr := header(false)
	hdr.Set("Content-Type", "text/plain; charset=utf-8")
	for k, v := range extra {
		hdr.Set(k, v)
	}
	applyHeaders(w.Header(), hdr)
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}
