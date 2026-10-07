package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// randRead and base64RawURL isolate the two primitives GenerateToken needs,
// keeping the token format identical to the original implementation:
// 32 random bytes, base64url encoded without padding.
func randRead(b []byte) (int, error) { return rand.Read(b) }

func base64RawURL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
