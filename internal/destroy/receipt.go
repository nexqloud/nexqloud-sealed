package destroy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/encoding/protojson"

	"nexqloud-sealed/internal/attest"
	"nexqloud-sealed/internal/destruction"
	"nexqloud-sealed/internal/receipt"
)

const Schema = "sealed-destruction/1"

type ZeroizationEvidence struct {
	WrapHash                  string `json:"wrap_hash"`
	CiphertextOverwritten     bool   `json:"ciphertext_overwritten"`
	ChipContributionDestroyed bool   `json:"chip_contribution_destroyed"`
	SaltRotated               bool   `json:"salt_rotated"`
}

type ReceiptInput struct {
	Priv            ed25519.PrivateKey
	Pub             ed25519.PublicKey
	OperatorID      string
	DestructionID   string
	TenantIDHash    string
	SeedCommit      string
	KeyVersion      int
	SaltEpoch       int
	AttestationJSON []byte
	Nonce           []byte
	Evidence        ZeroizationEvidence
}

func BuildReceipt(in ReceiptInput) (destruction.Receipt, error) {
	if in.Priv == nil || in.Pub == nil {
		return destruction.Receipt{}, fmt.Errorf("missing signing key")
	}
	if in.TenantIDHash == "" {
		return destruction.Receipt{}, fmt.Errorf("missing tenant_id_hash")
	}

	attHash, err := attest.ReportDigest(in.AttestationJSON)
	if err != nil {
		return destruction.Receipt{}, fmt.Errorf("attestation digest: %w", err)
	}

	evidenceJSON, err := json.Marshal(in.Evidence)
	if err != nil {
		return destruction.Receipt{}, err
	}

	pkg := map[string]any{
		"schema":                Schema,
		"destruction_id":        in.DestructionID,
		"operator_id":           in.OperatorID,
		"tenant_id_hash":        in.TenantIDHash,
		"seed_commit":           in.SeedCommit,
		"key_version":           in.KeyVersion,
		"attestation_hash":      attHash,
		"zeroization_evidence":  json.RawMessage(evidenceJSON),
		"salt_epoch":            in.SaltEpoch,
		"timestamp":             time.Now().UTC().Format(time.RFC3339),
	}

	canonical, err := receipt.Canonicalize(pkg)
	if err != nil {
		return destruction.Receipt{}, err
	}
	sig := ed25519.Sign(in.Priv, canonical)

	rcpt := destruction.Receipt{
		Package:   pkg,
		Signature: hex.EncodeToString(sig),
		Pubkey:    hex.EncodeToString(in.Pub),
	}
	if len(in.AttestationJSON) > 0 {
		rcpt.Attestation = json.RawMessage(in.AttestationJSON)
	}
	if len(in.Nonce) > 0 {
		rcpt.Nonce = hex.EncodeToString(in.Nonce)
		runtimeClaims, err := receipt.AzureRuntimeClaims(in.Pub, in.Nonce)
		if err != nil {
			return destruction.Receipt{}, fmt.Errorf("runtime claims: %w", err)
		}
		rcpt.RuntimeClaimsJSON = json.RawMessage(runtimeClaims)
	}

	att := &sevsnp.Attestation{}
	if len(in.AttestationJSON) > 0 {
		if err := protojson.Unmarshal(in.AttestationJSON, att); err == nil {
			rcpt.CertChain = receipt.EncodeCertificateChain(att.CertificateChain)
		}
	}
	return rcpt, nil
}

func TenantIDHash(tenantID string) string {
	sum := sha256.Sum256([]byte(tenantID))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func NewZeroizationEvidence(wrapHash string, ciphertextOverwritten, chipDestroyed, saltRotated bool) ZeroizationEvidence {
	return ZeroizationEvidence{
		WrapHash:                  wrapHash,
		CiphertextOverwritten:     ciphertextOverwritten,
		ChipContributionDestroyed: chipDestroyed,
		SaltRotated:               saltRotated,
	}
}

func RandomNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}
