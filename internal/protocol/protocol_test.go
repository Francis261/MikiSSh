package protocol

import (
	"bytes"
	"testing"
)

func TestRoundTripsTypedFrames(t *testing.T) {
	buf, err := Encode(TypeStdout, []byte("hello"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg, err := Decode(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msg.Type != TypeStdout {
		t.Errorf("type = %v, want %v", msg.Type, TypeStdout)
	}
	if !bytes.Equal(msg.Payload, []byte("hello")) {
		t.Errorf("payload = %q, want %q", msg.Payload, "hello")
	}
}

func TestRejectsEmptyFrames(t *testing.T) {
	_, err := Decode([]byte{})
	if !IsProtocolError(err) {
		t.Fatalf("want ProtocolError, got %v", err)
	}
}

func TestRejectsOversizedFrames(t *testing.T) {
	raw := make([]byte, MaxFrameBytes+64)
	_, err := Decode(raw)
	if !IsProtocolError(err) {
		t.Fatalf("want ProtocolError, got %v", err)
	}
}

func TestResizeRoundTripAndClamping(t *testing.T) {
	buf, err := EncodeResize(200, 50)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg, err := Decode(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	cols, rows, err := DecodeResize(msg.Payload)
	if err != nil {
		t.Fatalf("decodeResize: %v", err)
	}
	if cols != 200 || rows != 50 {
		t.Errorf("got cols=%d rows=%d, want 200/50", cols, rows)
	}

	// Out-of-range values saturate rather than wrap.
	clamped, err := EncodeResize(1_000_000_000, -5)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg, err = Decode(clamped)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	cols, rows, err = DecodeResize(msg.Payload)
	if err != nil {
		t.Fatalf("decodeResize: %v", err)
	}
	if cols != 65535 || rows != 0 {
		t.Errorf("got cols=%d rows=%d, want 65535/0", cols, rows)
	}
}

func TestJSONPayloadsParse(t *testing.T) {
	raw, err := EncodeJSON(TypeExit, map[string]int{"code": 3})
	if err != nil {
		t.Fatalf("encodeJSON: %v", err)
	}
	msg, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var payload map[string]int
	if err := msg.JSON(&payload); err != nil {
		t.Fatalf("json: %v", err)
	}
	if payload["code"] != 3 {
		t.Errorf("code = %d, want 3", payload["code"])
	}
}

func TestMalformedJSONThrowsProtocolError(t *testing.T) {
	raw, err := Encode(TypeExit, []byte("{nope"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var payload map[string]int
	if err := msg.JSON(&payload); !IsProtocolError(err) {
		t.Fatalf("want ProtocolError, got %v", err)
	}
}

func TestTypeNames(t *testing.T) {
	if got := TypeKex.String(); got != "KEX" {
		t.Errorf("TypeKex = %q, want KEX", got)
	}
	if got := Type(0x7e).String(); got != "UNKNOWN(0x7e)" {
		t.Errorf("unknown type = %q, want UNKNOWN(0x7e)", got)
	}
}
