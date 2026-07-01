package destroy

import (
	"crypto/ed25519"

	"nexqloud-sealed/internal/destruction"
)

type Proof = destruction.Proof

func Aggregate(want []string, got []Receipt, destructionID string, substrateSK ed25519.PrivateKey) (Proof, error) {
	receipts := make([]destruction.Receipt, len(got))
	for i, r := range got {
		receipts[i] = destruction.Receipt(r)
	}
	return destruction.Aggregate(want, receipts, destructionID, substrateSK)
}

func VerifyUnifiedProof(proof Proof, want []string, got []Receipt) error {
	receipts := make([]destruction.Receipt, len(got))
	for i, r := range got {
		receipts[i] = destruction.Receipt(r)
	}
	return destruction.VerifyProofMerkle(proof, want, receipts)
}
