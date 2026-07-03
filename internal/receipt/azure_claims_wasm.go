//go:build js && wasm

package receipt

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
)

func AzureRuntimeClaims(pub ed25519.PublicKey, nonce []byte) ([]byte, error) {
	keyHash := sha512.Sum512(append(append([]byte{}, pub...), nonce...))
	userData := hex.EncodeToString(keyHash[:])
	claims := map[string]any{
		"keys":             []any{},
		"vm-configuration": map[string]any{},
		"user-data":        userData,
	}
	return Canonicalize(claims)
}
