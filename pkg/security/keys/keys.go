// Package keys defines what a token-encryption key is: how to generate one, what
// forms are accepted, and how to decode one into AES key bytes.
//
// It is a leaf package on purpose. pkg/security imports pkg/config, so the key
// rules cannot live in pkg/security if pkg/config is to enforce them — and a
// length check duplicated in the config package is how the two drift apart. Both
// pkg/config's validation and pkg/security's cipher construction call in here, so
// there is one definition.
package keys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Size is the length in bytes of the key Generate produces: AES-256.
const Size = 32

// Generate returns a base64-encoded 32-byte key from crypto/rand, suitable for
// security.token_encryption_key.
//
// It exists because nothing else in the project produced one, and an
// administrator told "the key must be 32 bytes" types 32 memorable characters.
// That is a passphrase's worth of entropy — well under 100 bits — sitting in a
// 256-bit slot. The base64 form is 44 characters, so a full-entropy key is
// expressible in a YAML file.
func Generate() (string, error) {
	b, err := GenerateBytes()
	if err != nil {
		return "", err
	}
	defer Zero(b)
	return base64.StdEncoding.EncodeToString(b), nil
}

// GenerateBytes returns Size random bytes from crypto/rand: a key in the form
// aes.NewCipher wants, with no string ever made of it.
//
// Generate's base64 output is for a human to paste into a config file, and a Go
// string cannot be zeroized. Callers that only need a key for this process —
// see security.NewEphemeralEncryption — should take the bytes and skip the
// round trip through a form built for typing.
func GenerateBytes() ([]byte, error) {
	b := make([]byte, Size)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return b, nil
}

// Validate reports whether key is usable as an AES key, in the same terms Decode
// accepts.
func Validate(key string) error {
	k, err := Decode(key)
	if err != nil {
		return err
	}
	Zero(k)
	return nil
}

// base64KeyLen is the length of a standard-encoded 32-byte key: 44 characters.
const base64KeyLen = 44

// Decode turns a configured key string into AES key bytes.
//
// Two forms are accepted, checked in this order:
//
//  1. Raw: the string's own bytes, when there are exactly 16, 24, or 32 of them.
//     This is what 0.1.x and 0.2.0 accepted, and it is checked first so no
//     existing config can change meaning.
//  2. Base64: a standard-encoded 32 bytes, which is 44 characters — what Generate
//     emits. 44 is not a raw key length, so the two forms cannot be confused.
//
// Base64 is deliberately accepted only for 32-byte keys. A base64-encoded 16-byte
// key is 24 characters and a 24-byte key is 32 characters, both of which are
// themselves valid raw key lengths; accepting those would mean the same string
// could denote two different keys, and form 1 has to win for compatibility. There
// is no reason to want a shorter key anyway.
//
// Prefer the base64 form for anything new: 32 typeable characters cannot carry
// 256 bits of entropy.
func Decode(key string) ([]byte, error) {
	if isRawKeyLen(len(key)) {
		return []byte(key), nil
	}

	if len(key) == base64KeyLen {
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err == nil && len(decoded) == Size {
			return decoded, nil
		}
		return nil, fmt.Errorf(
			"is %d characters, the length of a base64-encoded 32-byte key, but is not "+
				"valid base64 for one (run `oauth2-pam-admin gen-key` to generate one)", base64KeyLen)
	}

	return nil, fmt.Errorf(
		"must be a base64-encoded 32 bytes (%d characters, from `oauth2-pam-admin gen-key`) "+
			"or 16, 24, or 32 raw bytes; got %d characters", base64KeyLen, len(key))
}

func isRawKeyLen(n int) bool {
	return n == 16 || n == 24 || n == 32
}

// Zero overwrites b with zeroes.
//
// Be clear about what this buys. It shortens the window in which a copy of key or
// token material sits in the process image, which matters for a core dump, a
// /proc/pid/mem read by root, or a later heap-inspecting bug. It does not
// guarantee the secret is gone: Go's garbage collector may have already copied
// the bytes elsewhere, the string form of a config value cannot be zeroed at all,
// and nothing here prevents the page from having been written to swap. Use it as
// hygiene on byte slices that held plaintext, not as a claim that the secret has
// been erased.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
