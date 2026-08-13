package security

import (
	"bytes"
	"strings"
	"testing"
)

const testKey = "0123456789abcdef0123456789abcdef" // 32 bytes → AES-256

func TestNewEncryptionKeyLengths(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"AES-128", strings.Repeat("a", 16), false},
		{"AES-192", strings.Repeat("a", 24), false},
		{"AES-256", strings.Repeat("a", 32), false},
		{"empty", "", true},
		{"too short", strings.Repeat("a", 15), true},
		{"between valid sizes", strings.Repeat("a", 20), true},
		{"too long", strings.Repeat("a", 33), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEncryption(tc.key)
			if tc.wantErr && err == nil {
				t.Errorf("NewEncryption(%d-byte key) = nil error, want an error", len(tc.key))
			}
			if !tc.wantErr && err != nil {
				t.Errorf("NewEncryption(%d-byte key): %v", len(tc.key), err)
			}
		})
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	e, err := NewEncryption(testKey)
	if err != nil {
		t.Fatalf("NewEncryption: %v", err)
	}

	inputs := [][]byte{
		[]byte("gho_16C7e42F292c6912E7710c838347Ae178B4a"),
		[]byte(""),
		[]byte("multi\nline\x00with NUL"),
		bytes.Repeat([]byte("x"), 4096),
	}

	for _, plaintext := range inputs {
		ciphertext, err := e.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if len(plaintext) > 0 && bytes.Contains(ciphertext, plaintext) {
			t.Error("the ciphertext contains the plaintext")
		}

		got, err := e.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("round trip returned %q, want %q", got, plaintext)
		}
	}
}

// TestEncryptIsNondeterministic: GCM must use a fresh nonce per call, otherwise
// two identical tokens produce identical ciphertexts and the keystream is reused.
func TestEncryptIsNondeterministic(t *testing.T) {
	e, err := NewEncryption(testKey)
	if err != nil {
		t.Fatalf("NewEncryption: %v", err)
	}

	plaintext := []byte("same token twice")
	first, err := e.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	second, err := e.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(first, second) {
		t.Error("encrypting the same plaintext twice produced identical output; the nonce is being reused")
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	e, err := NewEncryption(testKey)
	if err != nil {
		t.Fatalf("NewEncryption: %v", err)
	}
	other, err := NewEncryption("fedcba9876543210fedcba9876543210")
	if err != nil {
		t.Fatalf("NewEncryption: %v", err)
	}

	ciphertext, err := e.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := other.Decrypt(ciphertext); err == nil {
		t.Error("Decrypt succeeded with the wrong key")
	}
}

// TestDecryptRejectsTamperedCiphertext: GCM is authenticated, so a flipped bit
// must fail rather than return garbage the broker would treat as a token.
func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	e, err := NewEncryption(testKey)
	if err != nil {
		t.Fatalf("NewEncryption: %v", err)
	}

	ciphertext, err := e.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a bit in the body, and separately in the nonce.
	for _, i := range []int{len(ciphertext) - 1, 0} {
		tampered := append([]byte(nil), ciphertext...)
		tampered[i] ^= 0x01
		if _, err := e.Decrypt(tampered); err == nil {
			t.Errorf("Decrypt accepted ciphertext with byte %d flipped", i)
		}
	}
}

func TestDecryptShortInput(t *testing.T) {
	e, err := NewEncryption(testKey)
	if err != nil {
		t.Fatalf("NewEncryption: %v", err)
	}

	for _, data := range [][]byte{nil, {}, []byte("short")} {
		if _, err := e.Decrypt(data); err == nil {
			t.Errorf("Decrypt(%d bytes) succeeded, want an error", len(data))
		}
	}
}
