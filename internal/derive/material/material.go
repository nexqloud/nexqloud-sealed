package material

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"nexqloud-sealed/internal/devmode"
	"nexqloud-sealed/internal/rootsecret"
)

const KeyVersion = 1

func Seed() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("NEXQLOUD_OPERATOR_SEED"))
	if raw != "" {
		b, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("NEXQLOUD_OPERATOR_SEED: %w", err)
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("NEXQLOUD_OPERATOR_SEED must be 32 bytes, got %d", len(b))
		}
		return b, nil
	}
	sum := sha256.Sum256([]byte("sealed-dek-seed/1"))
	out := make([]byte, 32)
	copy(out, sum[:])
	return out, nil
}

func Chip() ([]byte, error) {
	if devmode.Enabled() {
		return DevChip(), nil
	}
	return rootsecret.Chip()
}

func DevChip() []byte {
	sum := sha256.Sum256([]byte("sealed-dek-chip/1"))
	out := make([]byte, 32)
	copy(out, sum[:])
	return out
}

func DevAttestBind() []byte {
	sum := sha256.Sum256([]byte("sealed-dek-attest-bind/1"))
	out := make([]byte, 32)
	copy(out, sum[:])
	return out
}

func AttestBindFromMeasurement(measurement []byte) []byte {
	if len(measurement) == 0 {
		return DevAttestBind()
	}
	sum := sha256.Sum256(measurement)
	out := make([]byte, 32)
	copy(out, sum[:])
	return out
}
