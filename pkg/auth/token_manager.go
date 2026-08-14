package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/security"
	"github.com/scttfrdmn/oauth2-pam/pkg/security/keys"
)

// TokenManager handles token lifecycle management including encrypted storage
// and periodic cleanup of expired tokens.
type TokenManager struct {
	config     *config.Config
	tokenStore *TokenStore
	encryption *security.Encryption
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// TokenStore is an in-memory token store with mutex protection.
type TokenStore struct {
	tokens map[string]*StoredToken
	mutex  sync.RWMutex
}

// StoredToken is a persisted token entry.
type StoredToken struct {
	ID           string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	UserID       string
	SessionID    string
	Fingerprint  string
	Encrypted    bool
	Metadata     map[string]string
	CreatedAt    time.Time
	LastUsed     time.Time
}

// NewTokenManager creates a new TokenManager.
//
// Encryption is on unless security.secure_token_storage is explicitly false. A
// configured token_encryption_key is used if present; otherwise the manager
// generates a per-process key, because the alternative — the previous behaviour —
// was to hold access tokens as plaintext in the heap for anyone who omitted a
// key, which is every administrator who took the shipped default. Tokens are
// never written anywhere, so a key that dies with the process costs nothing.
// See security.NewEphemeralEncryption for what that does and does not buy.
func NewTokenManager(cfg *config.Config) (*TokenManager, error) {
	var enc *security.Encryption
	switch {
	case !cfg.Security.SecureTokenStorage:
		log.Warn().Msg("security.secure_token_storage is false; access tokens will be held as plaintext in memory")
	case cfg.Security.TokenEncryptionKey != "":
		e, err := security.NewEncryption(cfg.Security.TokenEncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize token encryption: %w", err)
		}
		enc = e
	default:
		e, err := security.NewEphemeralEncryption()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize token encryption: %w", err)
		}
		enc = e
		log.Info().Msg("No security.token_encryption_key set; encrypting tokens under a per-process key")
	}

	return &TokenManager{
		config: cfg,
		tokenStore: &TokenStore{
			tokens: make(map[string]*StoredToken),
		},
		encryption: enc,
		stopChan:   make(chan struct{}),
	}, nil
}

// Start starts the token manager background cleanup goroutine.
func (tm *TokenManager) Start(ctx context.Context) error {
	log.Info().Msg("Starting token manager")
	tm.wg.Add(1)
	go tm.cleanup(ctx)
	return nil
}

// Stop shuts down the token manager.
func (tm *TokenManager) Stop() error {
	log.Info().Msg("Stopping token manager")
	close(tm.stopChan)
	tm.wg.Wait()
	return nil
}

// StoreToken stores an access token and returns its ID.
func (tm *TokenManager) StoreToken(sessionID, userID, accessToken, refreshToken string, expiresAt time.Time) (string, error) {
	tokenID, err := generateTokenID()
	if err != nil {
		return "", fmt.Errorf("generate token ID: %w", err)
	}

	stored := &StoredToken{
		ID:           tokenID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		UserID:       userID,
		SessionID:    sessionID,
		Fingerprint:  fingerprintToken(accessToken),
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
	}

	if tm.encryption != nil {
		// []byte(accessToken) is a fresh copy of the plaintext; zeroize it once the
		// ciphertext exists. The token's string form, and every copy the provider
		// and net/http already made of it, are beyond reach — see keys.Zero.
		plaintext := []byte(accessToken)
		defer keys.Zero(plaintext)

		encrypted, err := tm.encryption.Encrypt(plaintext)
		if err != nil {
			return "", fmt.Errorf("encrypt token: %w", err)
		}
		stored.AccessToken = string(encrypted)
		stored.Encrypted = true
	}

	tm.tokenStore.mutex.Lock()
	tm.tokenStore.tokens[tokenID] = stored
	tm.tokenStore.mutex.Unlock()

	return tokenID, nil
}

// Has reports whether a token is present and still within its own expiry.
//
// It exists because that is the whole question a caller asks when it needs to
// know if a session's credential is still there: GetDecryptedAccessToken answers
// it too, but at the price of an AES-GCM open and a plaintext access token in the
// heap for an answer that is thrown away. See #50.
//
// A pure read. It does not touch LastUsed and does not evict the expired record
// it may find — a predicate that mutates would make asking the question change
// the answer, and the callers are deciding whether to report a session
// authorized.
func (tm *TokenManager) Has(tokenID string) bool {
	if tokenID == "" {
		return false
	}

	tm.tokenStore.mutex.RLock()
	defer tm.tokenStore.mutex.RUnlock()

	stored, ok := tm.tokenStore.tokens[tokenID]
	return ok && stored.ExpiresAt.After(time.Now())
}

// RevokeToken removes a token from the store.
func (tm *TokenManager) RevokeToken(tokenID string) {
	tm.tokenStore.mutex.Lock()
	delete(tm.tokenStore.tokens, tokenID)
	tm.tokenStore.mutex.Unlock()
}

// cleanup periodically removes expired tokens.
func (tm *TokenManager) cleanup(ctx context.Context) {
	defer tm.wg.Done()

	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tm.stopChan:
			return
		case <-ticker.C:
			now := time.Now()
			var expired []string

			tm.tokenStore.mutex.RLock()
			for id, t := range tm.tokenStore.tokens {
				if t.ExpiresAt.Before(now) {
					expired = append(expired, id)
				}
			}
			tm.tokenStore.mutex.RUnlock()

			if len(expired) > 0 {
				tm.tokenStore.mutex.Lock()
				for _, id := range expired {
					delete(tm.tokenStore.tokens, id)
				}
				tm.tokenStore.mutex.Unlock()
				log.Debug().Int("count", len(expired)).Msg("Cleaned up expired tokens")
			}
		}
	}
}

func generateTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GetDecryptedAccessToken retrieves and decrypts the access token for tokenID.
func (tm *TokenManager) GetDecryptedAccessToken(tokenID string) (string, error) {
	tm.tokenStore.mutex.RLock()
	stored, ok := tm.tokenStore.tokens[tokenID]
	tm.tokenStore.mutex.RUnlock()

	if !ok {
		return "", fmt.Errorf("token not found: %s", tokenID)
	}
	if stored.ExpiresAt.Before(time.Now()) {
		return "", fmt.Errorf("token expired")
	}

	if !stored.Encrypted {
		return stored.AccessToken, nil
	}
	if tm.encryption == nil {
		return "", fmt.Errorf("token is encrypted but no encryption key configured")
	}
	decrypted, err := tm.encryption.Decrypt([]byte(stored.AccessToken))
	if err != nil {
		return "", fmt.Errorf("decrypt token: %w", err)
	}
	// string(decrypted) copies, so the slice can go back to zeroes immediately.
	defer keys.Zero(decrypted)
	return string(decrypted), nil
}

func fingerprintToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:16])
}
