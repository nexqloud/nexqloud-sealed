//go:build !(js && wasm)

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"

	"nexqloud-sealed/internal/enclave"
)

func AzureRuntimeClaims(pub ed25519.PublicKey, nonce []byte) ([]byte, error) {
	keyHash := enclave.KeyHash(pub, nonce)
	userData := hex.EncodeToString(keyHash[:])
	claims := map[string]any{
		"keys":             []any{},
		"vm-configuration": map[string]any{},
		"user-data":        userData,
	}
	return Canonicalize(claims)
}
