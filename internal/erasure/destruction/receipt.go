package destruction

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"nexqloud-sealed/internal/receipt"
)

func (r Receipt) TenantHash() string {
	if r.Package == nil {
		return ""
	}
	v, _ := r.Package["tenant_id_hash"].(string)
	return v
}

func (r Receipt) OperatorID() string {
	if r.Package == nil {
		return ""
	}
	v, _ := r.Package["operator_id"].(string)
	return v
}

func (r Receipt) DestructionID() string {
	if r.Package == nil {
		return ""
	}
	v, _ := r.Package["destruction_id"].(string)
	return v
}

func VerifyReceipt(r Receipt) error {
	if r.Package == nil {
		return fmt.Errorf("missing package")
	}
	schema, _ := r.Package["schema"].(string)
	if schema != ReceiptSchema && schema != ReceiptSchemaV2 {
		return fmt.Errorf("invalid schema %q", schema)
	}
	if r.OperatorID() == "" {
		return fmt.Errorf("missing operator_id")
	}
	if r.TenantHash() == "" {
		return fmt.Errorf("missing tenant_id_hash")
	}

	pub, err := hex.DecodeString(r.Pubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid pubkey")
	}

	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}

	canonical, err := receipt.Canonicalize(r.Package)
	if err != nil {
		return fmt.Errorf("canonicalize package: %w", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func (r Receipt) SaltEpoch() int {
	if r.Package == nil {
		return 0
	}
	switch v := r.Package["salt_epoch"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return 0
	}
}

func (r Receipt) AttestationHash() string {
	if r.Package == nil {
		return ""
	}
	v, _ := r.Package["attestation_hash"].(string)
	return v
}

func (r Receipt) ZeroizationEvidenceJSON() []byte {
	if r.Package == nil {
		return nil
	}
	raw, ok := r.Package["zeroization_evidence"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []byte:
		return v
	case json.RawMessage:
		return v
	default:
		b, _ := json.Marshal(v)
		return b
	}
}

func operatorsOf(got []Receipt) []string {
	ops := make([]string, 0, len(got))
	for _, r := range got {
		if op := r.OperatorID(); op != "" {
			ops = append(ops, op)
		}
	}
	sort.Strings(ops)
	return ops
}

func sameSet(want, got []string) bool {
	if len(want) != len(got) {
		return false
	}
	a := append([]string(nil), want...)
	b := append([]string(nil), got...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func canonicalLeaves(got []Receipt) [][]byte {
	sorted := append([]Receipt(nil), got...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].OperatorID() < sorted[j].OperatorID()
	})

	leaves := make([][]byte, 0, len(sorted))
	for _, r := range sorted {
		canonical, err := receipt.Canonicalize(r.Package)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(canonical)
		leaves = append(leaves, sum[:])
	}
	return leaves
}

func NewTestReceipt(priv ed25519.PrivateKey, destructionID, operatorID, tenantIDHash, seedCommit string, keyVersion int) (Receipt, error) {
	return buildReceipt(priv, destructionID, operatorID, tenantIDHash, seedCommit, "", keyVersion)
}

func BuildReceipt(priv ed25519.PrivateKey, destructionID, operatorID, tenantIDHash, seedCommit, wrapEvidence string, keyVersion int) (Receipt, error) {
	return buildReceipt(priv, destructionID, operatorID, tenantIDHash, seedCommit, wrapEvidence, keyVersion)
}

func buildReceipt(priv ed25519.PrivateKey, destructionID, operatorID, tenantIDHash, seedCommit, wrapEvidence string, keyVersion int) (Receipt, error) {
	pub := priv.Public().(ed25519.PublicKey)
	pkg := map[string]any{
		"schema":          ReceiptSchema,
		"destruction_id":  destructionID,
		"operator_id":     operatorID,
		"tenant_id_hash":  tenantIDHash,
		"seed_commit":     seedCommit,
		"key_version":     keyVersion,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}
	if wrapEvidence != "" {
		pkg["wrap_evidence"] = wrapEvidence
	}
	canonical, err := receipt.Canonicalize(pkg)
	if err != nil {
		return Receipt{}, err
	}
	sig := ed25519.Sign(priv, canonical)
	return Receipt{
		Package:   pkg,
		Signature: hex.EncodeToString(sig),
		Pubkey:    hex.EncodeToString(pub),
	}, nil
}
