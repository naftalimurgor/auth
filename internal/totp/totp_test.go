package totp

import (
	"testing"
	"time"
)

func TestRFC6238(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	tests := []struct {
		timestamp int64
		want      string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, tt := range tests {
		got, err := Generate(
			secret,
			time.Unix(tt.timestamp, 0),
			8,
		)
		if err != nil {
			t.Fatalf("Generate() error: %v", err)
		}
		if got != tt.want {
			t.Errorf("timestamp %d: got %s, want %s",
				tt.timestamp, got, tt.want)
		}
	}
}

func TestInvalidDigits(t *testing.T) {
	_, err := Generate(
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		time.Unix(59, 0),
		5,
	)
	if err == nil {
		t.Fatal("expected error for invalid digits")
	}
}
