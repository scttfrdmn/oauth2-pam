package auth

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

const (
	plaintextToken = "gho_16C7e42F292c6912E7710c838347Ae178B4a"
	encryptionKey  = "0123456789abcdef0123456789abcdef"
)

func tokenManagerConfig(key string) *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			SecureTokenStorage: key != "",
			TokenEncryptionKey: key,
		},
	}
}

func TestStoreAndRetrieveToken(t *testing.T) {
	tm, err := NewTokenManager(tokenManagerConfig(encryptionKey))
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	id, err := tm.StoreToken("sess-1", "alice", plaintextToken, "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}
	if id == "" {
		t.Fatal("StoreToken returned an empty token ID")
	}

	got, err := tm.GetDecryptedAccessToken(id)
	if err != nil {
		t.Fatalf("GetDecryptedAccessToken: %v", err)
	}
	if got != plaintextToken {
		t.Errorf("token = %q, want %q", got, plaintextToken)
	}
}

// TestStoredTokenIsNotPlaintext is the point of secure_token_storage: a memory
// dump of the broker must not hand over usable GitHub credentials.
func TestStoredTokenIsNotPlaintext(t *testing.T) {
	tm, err := NewTokenManager(tokenManagerConfig(encryptionKey))
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	id, err := tm.StoreToken("sess-1", "alice", plaintextToken, "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}

	tm.tokenStore.mutex.RLock()
	stored := tm.tokenStore.tokens[id]
	tm.tokenStore.mutex.RUnlock()

	if stored == nil {
		t.Fatal("token was not stored")
	}
	if !stored.Encrypted {
		t.Error("Encrypted = false, want true with an encryption key configured")
	}
	if stored.AccessToken == plaintextToken {
		t.Error("the access token is stored in plaintext")
	}
	if strings.Contains(stored.AccessToken, plaintextToken) {
		t.Error("the stored blob contains the plaintext token")
	}
	// The fingerprint identifies the token in logs without revealing it.
	if stored.Fingerprint == "" {
		t.Error("no fingerprint was recorded")
	}
	if strings.Contains(stored.Fingerprint, plaintextToken) {
		t.Error("the fingerprint leaks the token")
	}
	if stored.UserID != "alice" || stored.SessionID != "sess-1" {
		t.Errorf("stored = %+v, want the user and session recorded", stored)
	}
}

// TestStorageWithoutEncryptionKey documents the fallback: with no key the token
// is held in the clear, and the record says so rather than claiming otherwise.
func TestStorageWithoutEncryptionKey(t *testing.T) {
	tm, err := NewTokenManager(tokenManagerConfig(""))
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	id, err := tm.StoreToken("sess-1", "alice", plaintextToken, "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}

	tm.tokenStore.mutex.RLock()
	stored := tm.tokenStore.tokens[id]
	tm.tokenStore.mutex.RUnlock()

	if stored.Encrypted {
		t.Error("Encrypted = true with no key configured")
	}

	got, err := tm.GetDecryptedAccessToken(id)
	if err != nil {
		t.Fatalf("GetDecryptedAccessToken: %v", err)
	}
	if got != plaintextToken {
		t.Errorf("token = %q, want %q", got, plaintextToken)
	}
}

func TestNewTokenManagerRejectsBadKey(t *testing.T) {
	if _, err := NewTokenManager(tokenManagerConfig("too-short")); err == nil {
		t.Error("NewTokenManager accepted a key of invalid length")
	}
}

func TestGetUnknownToken(t *testing.T) {
	tm, err := NewTokenManager(tokenManagerConfig(encryptionKey))
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	if _, err := tm.GetDecryptedAccessToken("nope"); err == nil {
		t.Error("GetDecryptedAccessToken succeeded for an unknown token ID")
	}
}

// TestExpiredTokenIsNotReturned: an expired token must not be usable even while
// the cleanup ticker has yet to remove it.
func TestExpiredTokenIsNotReturned(t *testing.T) {
	tm, err := NewTokenManager(tokenManagerConfig(encryptionKey))
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	id, err := tm.StoreToken("sess-1", "alice", plaintextToken, "", time.Now().Add(-time.Second))
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}

	got, err := tm.GetDecryptedAccessToken(id)
	if err == nil {
		t.Fatalf("an expired token was returned: %q", got)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("err = %q, want it to say the token expired", err)
	}
}

func TestRevokeToken(t *testing.T) {
	tm, err := NewTokenManager(tokenManagerConfig(encryptionKey))
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	id, err := tm.StoreToken("sess-1", "alice", plaintextToken, "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}

	tm.RevokeToken(id)

	if _, err := tm.GetDecryptedAccessToken(id); err == nil {
		t.Error("a revoked token is still retrievable")
	}
	// Revoking twice, or revoking something unknown, must not panic.
	tm.RevokeToken(id)
	tm.RevokeToken("never-existed")
}

func TestTokenIDsAreUnique(t *testing.T) {
	tm, err := NewTokenManager(tokenManagerConfig(encryptionKey))
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		id, err := tm.StoreToken("sess", "alice", plaintextToken, "", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("StoreToken: %v", err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("token ID %q was issued twice", id)
		}
		seen[id] = struct{}{}
	}
}

func TestFingerprintIsStableAndDistinguishing(t *testing.T) {
	a := fingerprintToken(plaintextToken)
	b := fingerprintToken(plaintextToken)
	c := fingerprintToken(plaintextToken + "x")

	if a != b {
		t.Error("fingerprintToken is not deterministic")
	}
	if a == c {
		t.Error("two different tokens share a fingerprint")
	}
	if len(a) != 32 { // 16 bytes of SHA-256, hex-encoded
		t.Errorf("fingerprint length = %d, want 32 hex chars", len(a))
	}
}
