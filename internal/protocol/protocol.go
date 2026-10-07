// Package protocol implements the MikiSSh wire protocol.
//
// WebSocket already delimits messages, so each frame is simply:
//
//	+--------+---------------------------+
//	| type   | payload (type-dependent)  |
//	| 1 byte | 0..N bytes                |
//	+--------+---------------------------+
//
// Text payloads are UTF-8 JSON; binary payloads are raw bytes.
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Type is the one-byte frame discriminator.
type Type byte

// Frame types.
const (
	// handshake
	TypeAuthRequest Type = 0x01
	TypeAuthOK      Type = 0x02
	TypeAuthFail    Type = 0x03

	// terminal I/O
	TypeStdin  Type = 0x10
	TypeStdout Type = 0x11
	TypeStderr Type = 0x12

	// control
	TypeResize Type = 0x20
	TypePing   Type = 0x21
	TypePong   Type = 0x22
	TypeKex    Type = 0x23 // key exchange / re-auth challenge

	// lifecycle
	TypeExit  Type = 0x30
	TypeError Type = 0x3f
)

var typeNames = map[Type]string{
	TypeAuthRequest: "AUTH_REQUEST",
	TypeAuthOK:      "AUTH_OK",
	TypeAuthFail:    "AUTH_FAIL",
	TypeStdin:       "STDIN",
	TypeStdout:      "STDOUT",
	TypeStderr:      "STDERR",
	TypeResize:      "RESIZE",
	TypePing:        "PING",
	TypePong:        "PONG",
	TypeKex:         "KEX",
	TypeExit:        "EXIT",
	TypeError:       "ERROR",
}

// String renders the symbolic name, or UNKNOWN(0x..) for unregistered types.
func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(0x%x)", byte(t))
}

// MaxFrameBytes is the hard cap on a single frame. Anything larger is a
// protocol violation rather than a legitimate terminal write.
const MaxFrameBytes = 256 * 1024

// ProtocolError marks a framing violation as distinct from an I/O failure,
// so callers can reject the connection without logging a stack trace.
type ProtocolError struct{ Message string }

func (e *ProtocolError) Error() string { return e.Message }

func newProtocolErrorf(format string, a ...any) *ProtocolError {
	return &ProtocolError{Message: fmt.Sprintf(format, a...)}
}

// IsProtocolError reports whether err is a framing violation.
func IsProtocolError(err error) bool {
	_, ok := err.(*ProtocolError)
	return ok
}

// Encode frames a message type plus payload into a single WebSocket message.
func Encode(t Type, payload []byte) ([]byte, error) {
	if len(payload) > MaxFrameBytes {
		return nil, newProtocolErrorf("frame too large: %d", len(payload))
	}
	out := make([]byte, 1+len(payload))
	out[0] = byte(t)
	copy(out[1:], payload)
	return out, nil
}

// EncodeJSON frames a JSON payload. Callers already know their payloads are
// marshalable, so a marshal failure is a programming error.
func EncodeJSON(t Type, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", t, err)
	}
	return Encode(t, b)
}

// MustEncodeJSON is EncodeJSON for statically valid payloads.
func MustEncodeJSON(t Type, v any) []byte {
	b, err := EncodeJSON(t, v)
	if err != nil {
		panic(err)
	}
	return b
}

// Message is a decoded frame.
type Message struct {
	Type     Type
	TypeName string
	Payload  []byte
}

// Decode parses a raw WebSocket message.
func Decode(raw []byte) (*Message, error) {
	if len(raw) == 0 {
		return nil, newProtocolErrorf("empty frame")
	}
	if len(raw) > MaxFrameBytes+1 {
		return nil, newProtocolErrorf("frame too large: %d", len(raw))
	}
	t := Type(raw[0])
	return &Message{Type: t, TypeName: t.String(), Payload: raw[1:]}, nil
}

// JSON decodes the payload as JSON into v.
func (m *Message) JSON(v any) error {
	if err := json.Unmarshal(m.Payload, v); err != nil {
		return newProtocolErrorf("malformed JSON payload")
	}
	return nil
}

// clampU16 mirrors the original implementation: non-finite/truncated input
// collapses to 0, and anything out of range saturates.
func clampU16(n int) uint16 {
	if n < 0 {
		return 0
	}
	if n > 0xffff {
		return 0xffff
	}
	return uint16(n)
}

// EncodeResize frames a terminal resize: cols and rows as big-endian uint16.
func EncodeResize(cols, rows int) ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:], clampU16(cols))
	binary.BigEndian.PutUint16(buf[2:], clampU16(rows))
	return Encode(TypeResize, buf)
}

// DecodeResize parses a terminal resize payload.
func DecodeResize(payload []byte) (cols, rows uint16, err error) {
	if len(payload) < 4 {
		return 0, 0, newProtocolErrorf("short resize frame")
	}
	return binary.BigEndian.Uint16(payload[0:2]), binary.BigEndian.Uint16(payload[2:4]), nil
}
