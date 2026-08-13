package keys

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateProducesAUsableKey(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := Validate(key); err != nil {
		t.Errorf("Generate produced a key Validate rejects: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("Generate did not emit base64: %v", err)
	}
	if len(raw) != Size {
		t.Errorf("Generate produced %d key bytes, want %d", len(raw), Size)
	}
}

// TestGenerateIsRandom is a smoke test, not a randomness test: two identical keys
// out of crypto/rand would mean the key is not being read from it at all.
func TestGenerateIsRandom(t *testing.T) {
	seen := make(map[string]struct{}, 16)
	for i := 0; i < 16; i++ {
		key, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if _, dup := seen[key]; dup {
			t.Fatal("Generate returned the same key twice")
		}
		seen[key] = struct{}{}
	}
}

func TestDecode(t *testing.T) {
	b64 := func(n int) string {
		return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", n)))
	}

	tests := []struct {
		name     string
		key      string
		wantLen  int // 0 means "expect an error"
		wantSame bool
	}{
		{name: "raw 16", key: strings.Repeat("a", 16), wantLen: 16, wantSame: true},
		{name: "raw 24", key: strings.Repeat("a", 24), wantLen: 24, wantSame: true},
		{name: "raw 32", key: strings.Repeat("a", 32), wantLen: 32, wantSame: true},
		{name: "base64 32", key: b64(32), wantLen: 32},
		// A base64-encoded 16-byte key is 24 characters and a 24-byte key is 32,
		// both raw key lengths — so these are read as raw, per the documented rule.
		{name: "base64 16 is read as raw 24", key: b64(16), wantLen: 24, wantSame: true},
		{name: "base64 24 is read as raw 32", key: b64(24), wantLen: 32, wantSame: true},
		{name: "empty", key: ""},
		{name: "one byte short", key: strings.Repeat("a", 15)},
		{name: "between valid sizes", key: strings.Repeat("a", 20)},
		{name: "one byte long", key: strings.Repeat("a", 33)},
		{name: "44 characters that are not base64", key: strings.Repeat("!", 44)},
		{name: "not base64 and not a key length", key: "!!!not-a-key!!!"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(tc.key)
			if tc.wantLen == 0 {
				if err == nil {
					t.Fatalf("Decode(%q) = %d bytes, want an error", tc.key, len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("Decode(%q): %v", tc.key, err)
			}
			if len(got) != tc.wantLen {
				t.Errorf("Decode(%q) = %d bytes, want %d", tc.key, len(got), tc.wantLen)
			}
			if tc.wantSame && string(got) != tc.key {
				t.Errorf("Decode(%q) = %q; a raw-length key must decode to its own bytes", tc.key, got)
			}
		})
	}
}

// TestRawFormWinsOverBase64 pins the precedence rule. A 32-character key that
// happens to be valid base64 decodes to 24 bytes, and reading it that way would
// silently change the key derived from an existing config.
func TestRawFormWinsOverBase64(t *testing.T) {
	const key = "abcdefghijklmnopqrstuvwxyz012345" // 32 chars, all base64 alphabet

	if _, err := base64.StdEncoding.DecodeString(key); err != nil {
		t.Fatalf("test premise broken: %q is not valid base64: %v", key, err)
	}

	got, err := Decode(key)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(got) != key {
		t.Errorf("Decode(%q) = %q, want the raw bytes; a 0.2.0 config changed meaning", key, got)
	}
}

func TestValidateMatchesDecode(t *testing.T) {
	for _, key := range []string{"", "short", strings.Repeat("a", 32)} {
		_, decodeErr := Decode(key)
		validateErr := Validate(key)
		if (decodeErr == nil) != (validateErr == nil) {
			t.Errorf("Decode(%q) err=%v but Validate err=%v", key, decodeErr, validateErr)
		}
	}
}

func TestZero(t *testing.T) {
	b := []byte("secret material")
	Zero(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d = %d, want 0", i, c)
		}
	}
	Zero(nil) // must not panic
}
