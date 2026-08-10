package gpu

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"
)

// DevMockIssuerSeed is a fixed seed used only for NEXQLOUD_DEV mock certs.
var DevMockIssuerSeed = []byte("nexqloud-dev-wipe-issuer-seed!!!") // 32 bytes

func DevMockIssuerPubkeyHex() string {
	priv := ed25519.NewKeyFromSeed(DevMockIssuerSeed)
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func DevMockWorkerCommitment() string {
	return "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
}

func mockZeroizationCert(policyHash, nonce string) (map[string]any, error) {
	if len(DevMockIssuerSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("dev mock issuer seed must be %d bytes", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(DevMockIssuerSeed)
	cert := ZeroizationCert{
		Schema:           CertSchema,
		ClearanceID:      "mock-clearance-0001",
		GPUID:            "mock-gpu-0",
		Method:           MethodDevNoop,
		PolicyHash:       policyHash,
		Nonce:            nonce,
		WorkerCommitment: DevMockWorkerCommitment(),
		WipedAt:          time.Now().UTC().Format(time.RFC3339),
		Issuer:           "mock-gpu-attestation-service",
	}
	signed, err := SignCert(cert, priv)
	if err != nil {
		return nil, err
	}
	return CertToMap(signed)
}
