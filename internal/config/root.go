package config

import (
	"os"
	"path/filepath"
)

// FindRoot locates the project directory that contains the web UI.
//
// Relative paths in the configuration resolve against it rather than the
// process working directory, so the gateway behaves identically whether it
// is started by pm2, by a systemd unit, or by `go test` — the last of which
// runs with the package directory as its working directory.
func FindRoot() string {
	if r := os.Getenv("MIKISSH_ROOT"); r != "" {
		return r
	}

	var starts []string
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			starts = append(starts, filepath.Dir(resolved))
		} else {
			starts = append(starts, filepath.Dir(exe))
		}
	}

	for _, s := range starts {
		if dir := walkUpForRoot(s, 6); dir != "" {
			return dir
		}
	}
	if len(starts) > 0 {
		return starts[0]
	}
	return "."
}

func walkUpForRoot(from string, levels int) string {
	dir := from
	for i := 0; i <= levels; i++ {
		if rootExists(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

func rootExists(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, "public", "index.html"))
	return err == nil && !st.IsDir()
}

// ResolveAgainst makes p absolute, interpreting a relative p as a path
// beneath root. Absolute paths and empty strings are returned unchanged.
func ResolveAgainst(root, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Clean(filepath.Join(root, p))
}
