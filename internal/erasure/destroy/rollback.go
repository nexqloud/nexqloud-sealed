package destroy

import (
	"crypto/ed25519"
	"fmt"

	"nexqloud-sealed/internal/derive/kdf"
	"nexqloud-sealed/internal/erasure/destruction"
)

// AntiRollbackResult reports what the anti-rollback step actually did, so the
// destruction receipt records measured facts instead of assumptions.
type AntiRollbackResult struct {
	PreviousEpoch int
	SaltEpoch     int
	ChipZeroized  bool
	MarkLogIndex  string
}

// AntiRollback makes destruction irreversible. Two things happen: the chip-derived
// key material this operator holds is zeroized, and the federation salt the KDF is
// keyed with is rolled forward. Because kdf.DeriveDEKWithFederation mixes both the
// salt bytes and the epoch into the HKDF salt, the destroyed DEK can never be
// reproduced from a retained backup, and the roll is written to the transparency
// log as a DestructionMark.
//
// Honest limit: SNP_GET_DERIVED_KEY is deterministic per chip and cannot be
// destroyed by the guest, so what is destroyed here is the operator's copy of that
// material. Irreversibility comes from the salt roll, not from the chip.
func AntiRollback(chipSecret []byte, saltPath, tenantID string, signer ed25519.PrivateKey) (AntiRollbackResult, error) {
	result := AntiRollbackResult{}
	if len(chipSecret) == 0 {
		return result, fmt.Errorf("missing chip secret")
	}

	_, prevEpoch, err := kdf.FederationSaltBytes(saltPath)
	if err != nil {
		return result, fmt.Errorf("read federation salt: %w", err)
	}

	zeroize(chipSecret)
	result.ChipZeroized = allZero(chipSecret)

	epoch, _, err := kdf.RotateFederationSalt(saltPath)
	if err != nil {
		return result, fmt.Errorf("rotate federation salt: %w", err)
	}

	result.PreviousEpoch = prevEpoch
	result.SaltEpoch = epoch
	result.MarkLogIndex = destruction.AppendDestructionMark(
		signer,
		destruction.NewDestructionMark(tenantID, epoch),
	)
	return result, nil
}
