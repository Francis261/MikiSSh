package static_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Francis261/MikiSSh/internal/static"
	"github.com/Francis261/MikiSSh/public"
)

// get performs a request whose target path is set verbatim, so nothing can
// normalise away the dot segments a traversal test depends on.
//
// Path holds the decoded form and RawPath the literal wire form; giving both
// is what stops url.URL from re-escaping a %2f into %252f, which would turn
// an escape attempt into an inert lookup.
func get(t *testing.T, base, rawPath, method string) *http.Response {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		t.Fatalf("unescape %q: %v", rawPath, err)
	}
	req := &http.Request{
		Method: method,
		URL: &url.URL{
			Scheme:  u.Scheme,
			Host:    u.Host,
			Path:    decoded,
			RawPath: rawPath,
		},
		Header: http.Header{},
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawPath, err)
	}
	t.Cleanup(func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	})
	return resp
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// A standalone binary has no public/ directory anywhere on disk; the
// compiled-in copy has to carry the whole UI.
func TestServesEmbeddedUIWhenNothingIsOnDisk(t *testing.T) {
	h, err := static.New(filepath.Join(t.TempDir(), "absent"), true, public.FS)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp := get(t, srv.URL, "/", http.MethodGet)
	if resp.StatusCode != 200 {
		t.Errorf("/ status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}
	if got := resp.Header.Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors: %q", got)
	}
	if page := body(t, resp); !strings.Contains(page, "MIKISSH") {
		t.Error("embedded index does not mention MIKISSH")
	}

	js := get(t, srv.URL, "/vendor/xterm.js", http.MethodGet)
	if js.StatusCode != 200 {
		t.Errorf("/vendor/xterm.js status = %d, want 200", js.StatusCode)
	}
	if ct := js.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("xterm.js content-type = %q", ct)
	}
	io.Copy(io.Discard, js.Body)
	js.Body.Close()

	css := get(t, srv.URL, "/vendor/xterm.css", http.MethodGet)
	if css.StatusCode != 200 {
		t.Errorf("/vendor/xterm.css status = %d, want 200", css.StatusCode)
	}
	io.Copy(io.Discard, css.Body)
	css.Body.Close()

	// A file that only exists in the working tree must not be reachable
	// through the fallback.
	missing := get(t, srv.URL, "/nowhere.js", http.MethodGet)
	if missing.StatusCode != 404 {
		t.Errorf("unknown asset status = %d, want 404", missing.StatusCode)
	}
}

func TestEmbeddedServesConditionalAndHeadRequests(t *testing.T) {
	h, err := static.New(filepath.Join(t.TempDir(), "absent"), true, public.FS)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	first := get(t, srv.URL, "/vendor/xterm.css", http.MethodGet)
	etag := first.Header.Get("ETag")
	if etag == "" {
		t.Fatal("embedded asset served without an ETag")
	}
	io.Copy(io.Discard, first.Body)
	first.Body.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/vendor/xterm.css", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("If-None-Match", etag)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("conditional GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Errorf("conditional GET status = %d, want 304", resp.StatusCode)
	}

	head := get(t, srv.URL, "/vendor/xterm.css", http.MethodHead)
	if head.StatusCode != 200 {
		t.Errorf("HEAD status = %d, want 200", head.StatusCode)
	}
	if head.Header.Get("Content-Length") == "" {
		t.Error("HEAD response lacks Content-Length")
	}
	io.Copy(io.Discard, head.Body)
	head.Body.Close()
}

// An on-disk copy is the developer's live edit; it must win over the
// compiled-in snapshot.
func TestOnDiskCopyWinsOverEmbedded(t *testing.T) {
	dir := t.TempDir()
	const marker = "<html><body>EDITED_ON_DISK</body></html>"
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(marker), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "only-on-disk.css"), []byte("body{}"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	h, err := static.New(dir, true, public.FS)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp := get(t, srv.URL, "/", http.MethodGet)
	if got := body(t, resp); got != marker {
		t.Errorf("served %q, want the on-disk copy", got)
	}

	// Files only in the working tree still resolve.
	only := get(t, srv.URL, "/only-on-disk.css", http.MethodHead)
	if only.StatusCode != 200 {
		t.Errorf("on-disk-only asset status = %d, want 200", only.StatusCode)
	}
	io.Copy(io.Discard, only.Body)
	only.Body.Close()

	// And so do those only in the binary.
	vendored := get(t, srv.URL, "/vendor/xterm.js", http.MethodHead)
	if vendored.StatusCode != 200 {
		t.Errorf("embedded-only asset status = %d, want 200", vendored.StatusCode)
	}
	io.Copy(io.Discard, vendored.Body)
	vendored.Body.Close()
}

// The traversal guard runs before the embedded lookup, so a path that
// escapes root must be refused outright rather than resolved against the
// compiled-in tree.
func TestTraversalNeverReachesEmbeddedAssets(t *testing.T) {
	h, err := static.New(filepath.Join(t.TempDir(), "absent"), true, public.FS)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	for _, p := range []string{
		"/../go.mod",
		"/..%2fgo.mod",
		"/%2e%2e/%2e%2e/etc/passwd",
		"/vendor/../../go.mod",
	} {
		resp := get(t, srv.URL, p, http.MethodGet)
		switch resp.StatusCode {
		case http.StatusForbidden, http.StatusNotFound:
			// acceptable
		default:
			t.Errorf("%s -> %d, want 403/404", p, resp.StatusCode)
		}
		if resp.StatusCode == http.StatusOK {
			if b := body(t, resp); strings.Contains(b, "module github.com") {
				t.Errorf("%s leaked go.mod through the embedded fallback", p)
			}
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func TestDisabledHandlerNeverServesEmbeddedAssets(t *testing.T) {
	h, err := static.New(filepath.Join(t.TempDir(), "absent"), false, public.FS)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp := get(t, srv.URL, "/", http.MethodGet)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("/ status = %d, want 404 when the UI is disabled", resp.StatusCode)
	}
	if b := body(t, resp); strings.Contains(b, "MIKISSH") {
		t.Error("disabled handler still served the UI")
	}
}

func TestNewWithoutEmbeddedFSStillServesFromDisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<b>disk</b>"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	h, err := static.New(dir, true, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	if got := body(t, get(t, srv.URL, "/", http.MethodGet)); got != "<b>disk</b>" {
		t.Errorf("served %q, want %q", got, "<b>disk</b>")
	}
	if resp := get(t, srv.URL, "/absent", http.MethodGet); resp.StatusCode != http.StatusNotFound {
		t.Errorf("absent file status = %d, want 404", resp.StatusCode)
	}
}
