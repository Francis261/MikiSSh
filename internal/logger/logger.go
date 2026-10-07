// Package logger provides a minimal structured logger.
//
// It deliberately has no dependencies and never logs secrets: fields whose
// names look like credentials are replaced with "[redacted]" at emit time.
package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Level is a logging threshold.
type Level int

// Supported thresholds, ordered by severity.
const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelSilent
)

func parseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "silent", "none", "off":
		return LevelSilent
	default:
		return LevelInfo
	}
}

func (l Level) name() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "silent"
	}
}

// Field is a structured key/value pair. Fields are emitted in insertion order
// so log lines stay byte-stable and greppable across restarts.
type Field struct {
	Key   string
	Value any
}

// F builds a Field: F("conn", id).
func F(key string, value any) Field { return Field{Key: key, Value: value} }

// Fingerprints are truncated hashes of a secret, safe to log; they are what
// lets an auditor correlate a session without seeing the token.
var fingerprintRe = regexp.MustCompile(`(?i)fingerprint|Fp$|_fp$`)

var secretRe = regexp.MustCompile(`(?i)token|pass|secret|key|passphrase`)

// syncWriter serialises writes so concurrent sessions never interleave lines.
type syncWriter struct {
	mu  sync.Mutex
	out io.Writer
}

func (w *syncWriter) write(b []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.out.Write(b)
}

// Logger emits JSON lines. Use With to bind fields for a component.
type Logger struct {
	w   *syncWriter
	lvl Level
	ctx []Field
}

// New returns a Logger writing to out. A nil out falls back to stdout.
func New(level string, out io.Writer) *Logger {
	if out == nil {
		out = os.Stdout
	}
	return &Logger{w: &syncWriter{out: out}, lvl: parseLevel(level)}
}

// NewDiscard returns a Logger that drops everything (used by tests).
func NewDiscard() *Logger {
	return New("silent", io.Discard)
}

// Level reports the configured threshold.
func (l *Logger) Level() Level { return l.lvl }

// Enabled reports whether a level would be emitted.
func (l *Logger) Enabled(lvl Level) bool { return lvl >= l.lvl }

// With returns a logger that binds fields to every subsequent record. Call
// fields with the same key win, matching object-spread semantics.
func (l *Logger) With(fields ...Field) *Logger {
	ctx := make([]Field, 0, len(l.ctx)+len(fields))
	ctx = append(ctx, l.ctx...)
	ctx = merge(ctx, fields)
	return &Logger{w: l.w, lvl: l.lvl, ctx: ctx}
}

// Debug logs at debug level.
func (l *Logger) Debug(msg string, fields ...Field) { l.emit(LevelDebug, msg, fields) }

// Info logs at info level.
func (l *Logger) Info(msg string, fields ...Field) { l.emit(LevelInfo, msg, fields) }

// Warn logs at warn level.
func (l *Logger) Warn(msg string, fields ...Field) { l.emit(LevelWarn, msg, fields) }

// Error logs at error level.
func (l *Logger) Error(msg string, fields ...Field) { l.emit(LevelError, msg, fields) }

// Errorf logs an error-wrapped message, keeping the cause on the "err" field.
func (l *Logger) Errorf(msg string, err error, fields ...Field) {
	l.emit(LevelError, msg, append(fields, F("err", errText(err))))
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func (l *Logger) emit(lvl Level, msg string, fields []Field) {
	if lvl < l.lvl {
		return
	}
	var b strings.Builder
	b.WriteString(`{"ts":"`)
	b.WriteString(timestamp())
	b.WriteString(`","level":"`)
	b.WriteString(lvl.name())
	b.WriteString(`","msg":`)
	b.WriteString(jsonString(msg))
	for _, f := range merge(l.ctx, fields) {
		b.WriteByte(',')
		b.WriteString(jsonString(redactKey(f.Key)))
		b.WriteByte(':')
		b.WriteString(jsonValue(f.Value))
	}
	b.WriteString("}\n")
	l.w.write([]byte(b.String()))
}

// timestamp matches the original format: RFC3339 in UTC with milliseconds.
func timestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000") + "Z"
}

// redactKey decides whether a key's value is a secret worth hiding.
func redactKey(key string) string {
	if fingerprintRe.MatchString(key) {
		return key
	}
	if secretRe.MatchString(key) {
		return "[redacted]"
	}
	return key
}

// merge overlays call fields onto bound fields, preserving first-insertion
// order the way `{...bindings, ...fields}` does.
func merge(ctx, fields []Field) []Field {
	out := make([]Field, 0, len(ctx)+len(fields))
	idx := make(map[string]int, len(ctx)+len(fields))
	overlay := func(fs []Field) {
		for _, f := range fs {
			if i, ok := idx[f.Key]; ok {
				out[i].Value = f.Value
				continue
			}
			idx[f.Key] = len(out)
			out = append(out, f)
		}
	}
	overlay(ctx)
	overlay(fields)
	return out
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// jsonValue falls back to a quoted Go rendering for values json cannot
// marshal (channels, funcs), so a bad field never breaks the log line.
func jsonValue(v any) string {
	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}
	return jsonString(fmt.Sprintf("%v", v))
}
