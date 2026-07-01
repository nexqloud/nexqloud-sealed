package destruction

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"nexqloud-sealed/internal/enclave"
)

func LoadCoordinatorKey(hexSeed string) (ed25519.PrivateKey, error) {
	if hexSeed == "" {
		sk, _, err := enclave.Key()
		return sk, err
	}
	seed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("coordinator-key-hex length %d, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func CoordinatorPublicKey(sk ed25519.PrivateKey) ed25519.PublicKey {
	return sk.Public().(ed25519.PublicKey)
}
