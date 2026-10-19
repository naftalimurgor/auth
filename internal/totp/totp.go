package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Generate returns a time-based one-time password.
// secret must be a Base32-encoded secret.
// digits is typically 6 or 8.
func Generate(secret string, at time.Time, digits int) (string, error) {
	if digits < 6 || digits > 8 {
		return "", fmt.Errorf("digits must be between 6 and 8")
	}

	secret = strings.TrimRight(
		strings.ToUpper(strings.TrimSpace(secret)), "=",
	)

	key, err := base32.StdEncoding.
		WithPadding(base32.NoPadding).
		DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("invalid Base32 secret: %w", err)
	}
	if len(key) == 0 {
		return "", fmt.Errorf("secret must not be empty")
	}

	counter := uint64(at.Unix() / 30)

	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)

	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset : offset+4])
	value &= 0x7fffffff

	var modulus uint32 = 1
	for i := 0; i < digits; i++ {
		modulus *= 10
	}

	code := value % modulus
	return fmt.Sprintf("%0*d", digits, code), nil
}
