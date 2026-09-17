// Package keyscope models the key scope that a piece of sealed data belongs to.
//
// A scope is a registry tenant: it owns one random key seed, sealed per operator
// into that scope's commitment record. Two properties matter for invention 3:
//
//   - the seed is random and per scope, so destroying a scope's wraps destroys the
//     only copies of the material that can open that scope's ciphertext;
//   - scopes are independent, so erasing one conversation cannot make another
//     conversation (or the rest of the account) unrecoverable.
package keyscope

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ScopePrefix marks a registry tenant that belongs to a conversation key scope
// rather than to a whole account.
const ScopePrefix = "ks1"

// SeedSize is the length of a scope key seed, in bytes.
const SeedSize = 32

// NewSeed returns a fresh random scope seed.
func NewSeed() ([]byte, error) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return seed, nil
}

// SeedCommit is the registry commitment for a scope seed: sha256, hex encoded.
// The registry stores it so two operators cannot register different seeds under
// the same scope.
func SeedCommit(seed []byte) string {
	sum := sha256.Sum256(seed)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ID derives the opaque registry scope id for one conversation.
func ID(accountID, sessionID string) (string, error) {
	accountID = strings.TrimSpace(accountID)
	sessionID = strings.TrimSpace(sessionID)
	if accountID == "" || sessionID == "" {
		return "", fmt.Errorf("keyscope: account_id and session_id are required")
	}
	sum := sha256.Sum256([]byte(accountID + "|" + sessionID))
	return ScopePrefix + ":" + hex.EncodeToString(sum[:16]), nil
}

// IsScope reports whether a registry tenant id is a conversation key scope.
func IsScope(tenantID string) bool {
	return strings.HasPrefix(tenantID, ScopePrefix+":")
}

// ParseSeed decodes a hex encoded scope seed and validates its length.
func ParseSeed(seedHex string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil {
		return nil, fmt.Errorf("keyscope: seed must be hex: %w", err)
	}
	if len(raw) != SeedSize {
		return nil, fmt.Errorf("keyscope: seed must be %d bytes, got %d", SeedSize, len(raw))
	}
	return raw, nil
}
