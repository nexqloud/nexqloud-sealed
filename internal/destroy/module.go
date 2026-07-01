package destroy

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"

	"nexqloud-sealed/internal/destruction"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/registry"
	"nexqloud-sealed/internal/rootsecret"
	"nexqloud-sealed/internal/state"
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
	wrapEvidence := evidenceOf(wrap)

	chipSecret, err := chipSecretForDestroy()
	if err != nil {
		return Receipt{}, err
	}
	seed, err := state.Open(chipSecret, wrap)
	if err == nil {
		zeroize(seed)
	}
	zeroize(wrap)

	randomBytes := make([]byte, 64)
	if _, err := randRead(randomBytes); err != nil {
		return Receipt{}, err
	}
	ciphertextOverwritten := overwriteCiphertext(tenantID, randomBytes) == nil
	if store := runtime.LocalStore; store != nil {
		_ = store.OverwriteWrap(tenantID, randomBytes)
	}

	saltPath := runtime.SaltPath
	if saltPath == "" {
		saltPath = filepath.Join(stateDir(), "federation_salt.json")
	}
	saltEpoch, err := AntiRollback(chipSecret, saltPath)
	if err != nil {
		return Receipt{}, err
	}

	evidence := NewZeroizationEvidence(wrapEvidence, ciphertextOverwritten, true, true)
	return newReceipt(req, TenantIDHash(tenantID), saltEpoch, evidence)
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
	return rootsecret.Chip()
}

func stateDir() string {
	if runtime.StateDir != "" {
		return runtime.StateDir
	}
	return "."
}
