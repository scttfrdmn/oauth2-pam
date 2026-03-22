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
	"github.com/scttfrdmn/pam-oauth2/pkg/config"
	"github.com/scttfrdmn/pam-oauth2/pkg/security"
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
	Metadata     map[string]interface{}
	CreatedAt    time.Time
	LastUsed     time.Time
}

// NewTokenManager creates a new TokenManager.
func NewTokenManager(cfg *config.Config) (*TokenManager, error) {
	var enc *security.Encryption
	if cfg.Security.SecureTokenStorage && cfg.Security.TokenEncryptionKey != "" {
		e, err := security.NewEncryption(cfg.Security.TokenEncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize token encryption: %w", err)
		}
		enc = e
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
		encrypted, err := tm.encryption.Encrypt([]byte(accessToken))
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

// GetToken retrieves a stored token by ID.
func (tm *TokenManager) GetToken(tokenID string) (*StoredToken, error) {
	tm.tokenStore.mutex.RLock()
	stored, ok := tm.tokenStore.tokens[tokenID]
	tm.tokenStore.mutex.RUnlock()

	if !ok {
		return nil, fmt.Errorf("token not found: %s", tokenID)
	}
	if stored.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	stored.LastUsed = time.Now()
	return stored, nil
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

func fingerprintToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:8])
}
