package destroy

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"path/filepath"

	"nexqloud-sealed/internal/derive/material"
	"nexqloud-sealed/internal/derive/state"
	"nexqloud-sealed/internal/erasure/destruction"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/registry"
)

type Receipt = destruction.Receipt

type RuntimeConfig struct {
	CoordinatorPub ed25519.PublicKey
	JWKSURL        string
	OperatorID     string
	StateDir       string
	SaltPath       string
	LocalStore     *registry.LocalStore
	ChipSecret     func() ([]byte, error)
	Attestation    func(pub ed25519.PublicKey, nonce []byte) ([]byte, error)
	SignReceipt    func(input ReceiptInput) (Receipt, error)
	// MarkSigner is the operator key used to sign the anti-rollback
	// DestructionMark that is written to the transparency log. Optional: when it
	// is unset the destruction still completes, but the roll is not published.
	MarkSigner ed25519.PrivateKey
	// DestroyRegistryWrap zeroes the registry-held wrap for a tenant. Set by the
	// operator so a destruction survives a restart; nil skips the step.
	DestroyRegistryWrap func(tenantID string) error
}

var runtime RuntimeConfig

func Configure(rt RuntimeConfig) {
	runtime = rt
}

func Destroy(req destruction.SignedDestroyReq, tenantID string) (Receipt, error) {
	if err := destruction.VerifyCoordinatorSig(runtime.CoordinatorPub, req); err != nil {
		return Receipt{}, err
	}
	if err := verifyCustomerSig(req.CustomerSig, tenantID); err != nil {
		return Receipt{}, err
	}
	if req.TenantID != tenantID {
		return Receipt{}, fmt.Errorf("tenant_id mismatch")
	}
	if req.OperatorID != "" && runtime.OperatorID != "" && req.OperatorID != runtime.OperatorID {
		return Receipt{}, fmt.Errorf("operator_id mismatch")
	}

	wrap, err := registry.LocalWrap(tenantID)
	if err != nil {
		return Receipt{}, err
	}
	wrapEvidence := evidenceOf(wrap) // hash of the material that is about to be erased

	chipSecret, err := chipSecretForDestroy()
	if err != nil {
		return Receipt{}, err
	}
	seed, err := state.Open(chipSecret, wrap)
	if err == nil {
		zeroize(seed)
	}
	zeroize(wrap)
	keyMaterialErased := allZero(wrap)

	randomBytes := make([]byte, 64)
	if _, err := randRead(randomBytes); err != nil {
		return Receipt{}, err
	}
	// Each evidence flag below is measured after the write rather than asserted:
	// a receipt that claims zeroization has to show the material is actually gone.
	ciphertextOverwritten := overwriteCiphertext(tenantID, randomBytes) == nil
	storeOverwritten := true
	if store := runtime.LocalStore; store != nil {
		storeOverwritten = store.OverwriteWrap(tenantID, randomBytes) == nil
	}

	saltPath := runtime.SaltPath
	if saltPath == "" {
		saltPath = filepath.Join(stateDir(), "federation_salt.json")
	}
	roll, err := AntiRollback(chipSecret, saltPath, tenantID, runtime.MarkSigner)
	if err != nil {
		return Receipt{}, err
	}
	if roll.MarkLogIndex != "" {
		log.Printf("destruction %s anti-rollback: salt epoch %d -> %d, mark log_index=%s",
			req.DestructionID, roll.PreviousEpoch, roll.SaltEpoch, roll.MarkLogIndex)
	}
	if !keyMaterialErased || !roll.ChipZeroized {
		return Receipt{}, fmt.Errorf("key material was not zeroized")
	}
	if roll.SaltEpoch <= roll.PreviousEpoch {
		return Receipt{}, fmt.Errorf("anti-rollback did not roll the federation salt (epoch %d)", roll.SaltEpoch)
	}

	// Last step, once everything else succeeded: make the erasure durable in the
	// registry as well. Without this an operator restart refetches the wrap and the
	// key material is recoverable again, which would make the receipt a lie.
	if runtime.DestroyRegistryWrap != nil {
		if err := runtime.DestroyRegistryWrap(tenantID); err != nil {
			return Receipt{}, fmt.Errorf("destroy registry wrap: %w", err)
		}
	} else {
		log.Printf("destruction %s: no registry wrap destroyer configured — the registry copy was NOT erased", req.DestructionID)
	}

	evidence := NewZeroizationEvidence(
		wrapEvidence,
		ciphertextOverwritten && storeOverwritten,
		keyMaterialErased && roll.ChipZeroized,
		roll.SaltEpoch > roll.PreviousEpoch,
	)
	return newReceipt(req, TenantIDHash(tenantID), roll.SaltEpoch, evidence)
}

func verifyCustomerSig(customerSig []byte, tenantID string) error {
	if runtime.JWKSURL == "" {
		return fmt.Errorf("jwks url not configured")
	}
	return identity.VerifySig(customerSig, tenantID, runtime.JWKSURL)
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func overwriteCiphertext(tenantID string, data []byte) error {
	dir := stateDir()
	path := filepath.Join(dir, tenantID+".bin")
	if err := mkdirAll(dir); err != nil {
		return err
	}
	return writeFile(path, data)
}

func evidenceOf(wrap []byte) string {
	return destruction.WrapEvidence(wrap)
}

func newReceipt(req destruction.SignedDestroyReq, tenantIDHash string, saltEpoch int, evidence ZeroizationEvidence) (Receipt, error) {
	if runtime.SignReceipt == nil {
		return Receipt{}, fmt.Errorf("receipt signer not configured")
	}
	return runtime.SignReceipt(ReceiptInput{
		DestructionID: req.DestructionID,
		TenantIDHash:  tenantIDHash,
		SeedCommit:    req.SeedCommit,
		KeyVersion:    req.KeyVersion,
		SaltEpoch:     saltEpoch,
		Evidence:      evidence,
		OperatorID:    runtime.OperatorID,
	})
}

func chipSecretForDestroy() ([]byte, error) {
	if runtime.ChipSecret != nil {
		return runtime.ChipSecret()
	}
	// material.Chip resolves the dev chip in dev mode and the real SNP derived key
	// in production, so the operator binary is runnable locally without a TEE.
	return material.Chip()
}

func stateDir() string {
	if runtime.StateDir != "" {
		return runtime.StateDir
	}
	return "."
}
