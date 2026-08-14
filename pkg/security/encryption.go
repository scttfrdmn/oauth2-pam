package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"

	"github.com/scttfrdmn/oauth2-pam/pkg/security/keys"
)

// Encryption provides AES-GCM symmetric encryption for token storage.
// It is safe for concurrent use.
type Encryption struct {
	// mu guards gcm against Destroy running concurrently with Encrypt/Decrypt.
	// Read-locking costs tens of nanoseconds against an AES-GCM operation's
	// microseconds, so this is not a hot-path concern.
	mu  sync.RWMutex
	gcm cipher.AEAD
}

// NewEncryption creates an Encryption instance from a key string, in either of
// the forms keys.Decode accepts.
func NewEncryption(key string) (*Encryption, error) {
	k, err := keys.Decode(key)
	if err != nil {
		return nil, fmt.Errorf("encryption key %w", err)
	}
	return newEncryption(k)
}

// NewEphemeralEncryption creates an Encryption instance under a fresh key from
// crypto/rand that exists only for the life of this process.
//
// This is for data that is never persisted, where the point of encryption is to
// keep plaintext out of the process image rather than to be able to read
// something back later. Tokens are exactly that: they live in a map in memory
// and are gone at shutdown, so nothing is lost by the key being unrecoverable —
// there will never be a ciphertext left to decrypt.
//
// It means an administrator who sets no token_encryption_key gets AES-256-GCM
// instead of plaintext. That is a real improvement over nothing, and it is not
// as good as a configured key: the key bytes sit in this process's heap, so an
// attacker who can read that memory has both halves. What it defends against is
// the narrower and more common case — a core dump, a heap-inspecting bug, a page
// that reached swap — where the ciphertext travels and the round keys do not.
func NewEphemeralEncryption() (*Encryption, error) {
	k, err := keys.GenerateBytes()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral encryption key: %w", err)
	}
	return newEncryption(k)
}

// newEncryption builds the AEAD from raw key bytes and zeroizes them.
func newEncryption(k []byte) (*Encryption, error) {
	// aes.NewCipher copies the key into its expanded round keys, so this copy is
	// dead weight the moment the cipher exists. See keys.Zero for what that is
	// worth.
	defer keys.Zero(k)

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

// Destroy drops the cipher, after which Encrypt and Decrypt return an error
// rather than panicking. Call it when a key is rotated out or at shutdown.
//
// What this buys: the AEAD becomes unreachable, so the runtime is free to reclaim
// the memory holding its expanded round keys. What it does not buy: those round
// keys are not zeroized — crypto/aes does not expose them — so the key material
// survives in freed memory until something else overwrites it. Destroy is a
// tidiness measure, not an erasure guarantee. See keys.Zero.
func (e *Encryption) Destroy() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gcm = nil
}

// Encrypt encrypts plaintext and returns nonce+ciphertext.
func (e *Encryption) Encrypt(plaintext []byte) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.gcm == nil {
		return nil, fmt.Errorf("encryption has been destroyed")
	}

	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return e.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts nonce+ciphertext produced by Encrypt.
func (e *Encryption) Decrypt(data []byte) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.gcm == nil {
		return nil, fmt.Errorf("encryption has been destroyed")
	}

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
