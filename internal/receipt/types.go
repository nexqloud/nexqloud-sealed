package receipt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/go-sev-guest/proto/sevsnp"
)

type Package struct {
	Schema             string         `json:"schema"`
	ReceiptID          string         `json:"receipt_id"`
	Timestamp          string         `json:"timestamp"`
	PromptHash         string         `json:"prompt_hash"`
	ResponseHash       string         `json:"response_hash"`
	ModelCommitment    string         `json:"model_commitment"`
	EnclaveMeasurement string         `json:"enclave_measurement"`
	GPUPolicyHash      string         `json:"gpu_policy_hash"`
	ZeroizationCert    map[string]any `json:"zeroization_cert"`
	IdentityClaimHash  string         `json:"identity_claim_hash"`
	Nonce              string         `json:"nonce"`
}

type CertificateChain struct {
	VCEK string `json:"vcek"`
	ASK  string `json:"ask,omitempty"`
	ARK  string `json:"ark,omitempty"`
}

type SealedReceipt struct {
	Package           Package           `json:"package"`
	Signature         string            `json:"signature"`
	Pubkey            string            `json:"pubkey"`
	Attestation       json.RawMessage   `json:"attestation"`
	CertChain         CertificateChain  `json:"cert_chain"`
	RuntimeClaimsJSON json.RawMessage   `json:"runtime_claims_json"`
	LogIndex          string            `json:"log_index"`
}

func EncodeCertificateChain(chain *sevsnp.CertificateChain) CertificateChain {
	if chain == nil {
		return CertificateChain{}
	}
	out := CertificateChain{
		VCEK: encodeDER(chain.VcekCert),
		ASK:  encodeDER(chain.AskCert),
		ARK:  encodeDER(chain.ArkCert),
	}
	return out
}

func DecodeCertificateChain(chain CertificateChain) (*sevsnp.CertificateChain, error) {
	vcek, err := decodeDER(chain.VCEK)
	if err != nil {
		return nil, fmt.Errorf("vcek: %w", err)
	}
	if len(vcek) == 0 {
		return nil, fmt.Errorf("vcek: missing certificate")
	}

	ask, err := decodeOptionalDER(chain.ASK)
	if err != nil {
		return nil, fmt.Errorf("ask: %w", err)
	}
	ark, err := decodeOptionalDER(chain.ARK)
	if err != nil {
		return nil, fmt.Errorf("ark: %w", err)
	}

	return &sevsnp.CertificateChain{
		VcekCert: vcek,
		AskCert:  ask,
		ArkCert:  ark,
	}, nil
}

func encodeDER(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(der)
}

func decodeDER(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func decodeOptionalDER(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return decodeDER(value)
}
