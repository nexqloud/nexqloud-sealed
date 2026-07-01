package destruction

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"nexqloud-sealed/internal/receipt"
)

type SignedDestroyReq struct {
	DestructionID       string `json:"destruction_id"`
	TenantID            string `json:"tenant_id"`
	KeyVersion          int    `json:"key_version"`
	SeedCommit          string `json:"seed_commit"`
	OperatorID          string `json:"operator_id"`
	AggregatorSubmitURL string `json:"aggregator_submit_url"`
	CustomerSig         []byte `json:"customer_sig"`
	CoordinatorSig      string `json:"coordinator_sig"`
}

func signPayload(req SignedDestroyReq) map[string]any {
	return map[string]any{
		"destruction_id":        req.DestructionID,
		"tenant_id":             req.TenantID,
		"key_version":           req.KeyVersion,
		"seed_commit":           req.SeedCommit,
		"operator_id":           req.OperatorID,
		"aggregator_submit_url": req.AggregatorSubmitURL,
		"customer_sig":          req.CustomerSig,
	}
}

func SignDispatch(priv ed25519.PrivateKey, req SignedDestroyReq) (string, error) {
	canonical, err := receipt.Canonicalize(signPayload(req))
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, canonical)
	return hex.EncodeToString(sig), nil
}

func VerifyCoordinatorSig(pub ed25519.PublicKey, req SignedDestroyReq) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("coordinator pubkey not configured")
	}
	if req.CoordinatorSig == "" {
		return fmt.Errorf("missing coordinator signature")
	}
	sig, err := hex.DecodeString(req.CoordinatorSig)
	if err != nil {
		return fmt.Errorf("invalid coordinator signature encoding")
	}
	canonical, err := receipt.Canonicalize(signPayload(req))
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return fmt.Errorf("coordinator signature verification failed")
	}
	return nil
}
