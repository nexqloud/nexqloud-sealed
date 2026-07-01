package destruction

import (
	"encoding/json"

	"nexqloud-sealed/internal/receipt"
)

const (
	ReceiptSchema      = "sealed-destruction-receipt/1"
	ReceiptSchemaV2    = "sealed-destruction/1"
	ProofSchema        = "sealed-destruction-proof/1"
)

type Receipt struct {
	Package           map[string]any           `json:"package"`
	Signature         string                   `json:"signature"`
	Pubkey            string                   `json:"pubkey"`
	Attestation       json.RawMessage          `json:"attestation,omitempty"`
	CertChain         receipt.CertificateChain `json:"cert_chain,omitempty"`
	RuntimeClaimsJSON json.RawMessage          `json:"runtime_claims_json,omitempty"`
	Nonce             string                   `json:"nonce,omitempty"`
}
