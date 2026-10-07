// Package public holds the web terminal's static assets.
//
// They are compiled into the gateway binary so that a standalone install —
// one file dropped into /usr/local/bin — still serves the UI with no
// sibling public/ directory on disk.
//
// The on-disk copy always wins when it exists (the repository layout that
// pm2 runs from), so editing public/ in a working tree needs no rebuild.
package public

import "embed"

// FS is the compiled copy of the UI.
//
//go:embed index.html vendor
var FS embed.FS
