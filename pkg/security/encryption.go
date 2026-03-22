package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Encryption provides AES-GCM symmetric encryption for token storage.
type Encryption struct {
	gcm cipher.AEAD
}

// NewEncryption creates an Encryption instance from a key string.
// The key must be 16, 24, or 32 bytes (AES-128, AES-192, or AES-256).
func NewEncryption(key string) (*Encryption, error) {
	k := []byte(key)
	switch len(k) {
	case 16, 24, 32:
		// valid
	default:
		return nil, fmt.Errorf("encryption key must be 16, 24, or 32 bytes; got %d", len(k))
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &Encryption{gcm: gcm}, nil
}

// Encrypt encrypts plaintext and returns nonce+ciphertext.
func (e *Encryption) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return e.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts nonce+ciphertext produced by Encrypt.
func (e *Encryption) Decrypt(data []byte) ([]byte, error) {
	nonceSize := e.gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
