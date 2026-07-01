package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/encoding/protojson"

	"nexqloud-sealed/internal/attest"
	"nexqloud-sealed/internal/destruction"
	"nexqloud-sealed/internal/destroy"
	"nexqloud-sealed/internal/registry"
)

type DeletionResult struct {
	OverallOK     bool    `json:"overall_ok"`
	Checks        []Check `json:"checks"`
	LogIndex      string  `json:"log_index"`
	DestructionID string  `json:"destruction_id,omitempty"`
	TenantIDHash  string  `json:"tenant_id_hash,omitempty"`
	Error         string  `json:"error,omitempty"`
}

func VerifyDeletion(proof destruction.Proof, receipts []destruction.Receipt, registryURL, tenantID string, challengeHex string, rootsCatalog map[string]HardwareRoots) DeletionResult {
	result := DeletionResult{
		LogIndex: proof.LogIndex,
	}

	if proof.Package != nil {
		if id, ok := proof.Package["destruction_id"].(string); ok {
			result.DestructionID = id
		}
		if hash, ok := proof.Package["tenant_id_hash"].(string); ok {
			result.TenantIDHash = hash
		}
	}

	for _, rcpt := range receipts {
		result.Checks = append(result.Checks, verifyDestructionReceipt(rcpt, challengeHex, rootsCatalog)...)
	}

	want, err := registryQuorum(registryURL, tenantID)
	if err != nil {
		result.Checks = append(result.Checks, Check{
			ID:     "registry_quorum",
			Label:  "Registry Quorum",
			Detail: err.Error(),
		})
	} else {
		got := operatorIDs(receipts)
		ok := sameOperatorSet(want, got)
		detail := fmt.Sprintf("registry=%v receipts=%v", want, got)
		if ok {
			detail = "destruction quorum matches registry wraps"
		}
		result.Checks = append(result.Checks, Check{
			ID:     "registry_quorum",
			Label:  "Registry Quorum",
			OK:     ok,
			Detail: detail,
		})
	}

	result.Checks = append(result.Checks, checkUnifiedProof(proof, receipts)...)

	result.OverallOK = true
	for _, c := range result.Checks {
		if !c.OK {
			result.OverallOK = false
		}
	}
	return result
}

func verifyDestructionReceipt(rcpt destruction.Receipt, challengeHex string, rootsCatalog map[string]HardwareRoots) []Check {
	checks := []Check{}

	if err := destruction.VerifyReceipt(rcpt); err != nil {
		checks = append(checks, Check{ID: "signature_valid", Label: "Signature Valid", Detail: err.Error()})
	} else {
		checks = append(checks, Check{ID: "signature_valid", Label: "Signature Valid", OK: true, Detail: "Ed25519 signature verified"})
	}

	pub, err := hex.DecodeString(rcpt.Pubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		checks = append(checks, Check{ID: "hardware_genuine", Label: "Hardware Genuine", Detail: "invalid pubkey"})
		return checks
	}
	publicKey := ed25519.PublicKey(pub)

	att := &sevsnp.Attestation{}
	if len(rcpt.Attestation) > 0 && string(rcpt.Attestation) != "{}" {
		if err := protojson.Unmarshal(rcpt.Attestation, att); err != nil {
			checks = append(checks, Check{ID: "hardware_genuine", Label: "Hardware Genuine", Detail: err.Error()})
			return checks
		}
	}

	chain := rcpt.CertChain
	if chain.VCEK == "" && att != nil {
		chain = resolveCertChain(chain, att)
	}
	roots := pickHardwareRoots(att, rootsCatalog)
	checks = append(checks, checkHardware(att, chain, roots))

	nonceHex := rcpt.Nonce
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != 32 {
		checks = append(checks, Check{ID: "key_binding", Label: "Key Bound to Silicon", Detail: "invalid nonce"})
	} else {
		checks = append(checks, checkKeyBinding(att, chain, publicKey, nonce, rcpt.RuntimeClaimsJSON))
	}

	checks = append(checks, checkDestructionAttestationHash(rcpt.Package, rcpt.Attestation))
	checks = append(checks, checkDestructionZeroizationEvidence(rcpt.Package))
	checks = append(checks, checkDestructionSaltEpoch(rcpt.Package))
	checks = append(checks, checkDestructionTenantHash(rcpt.Package))
	if nonceHex != "" {
		checks = append(checks, checkFreshness(nonceHex, challengeHex))
	}

	op := rcpt.OperatorID()
	checks = append(checks, Check{
		ID:     "destruction_operator_id:" + op,
		Label:  "Operator " + op,
		OK:     op != "",
		Detail: op,
	})
	return checks
}

func checkDestructionAttestationHash(pkg map[string]any, attRaw json.RawMessage) Check {
	check := Check{ID: "destruction_attestation_hash", Label: "Attestation Hash"}
	expected, _ := pkg["attestation_hash"].(string)
	check.Hash = truncateHex(stringsTrimPrefix(expected, "sha256:"))
	if expected == "" {
		check.Detail = "missing attestation_hash"
		return check
	}
	actual, err := attest.ReportDigest(attRaw)
	if err != nil {
		check.Detail = err.Error()
		return check
	}
	if actual != expected {
		check.Detail = fmt.Sprintf("want %s got %s", expected, actual)
		return check
	}
	check.OK = true
	check.Detail = expected
	return check
}

func checkDestructionZeroizationEvidence(pkg map[string]any) Check {
	check := Check{ID: "zeroization_evidence", Label: "Zeroization Evidence"}
	raw, ok := pkg["zeroization_evidence"]
	if !ok {
		check.Detail = "missing zeroization_evidence"
		return check
	}
	data, err := json.Marshal(raw)
	if err != nil {
		check.Detail = err.Error()
		return check
	}
	var evidence destroy.ZeroizationEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		check.Detail = err.Error()
		return check
	}
	if evidence.WrapHash == "" {
		check.Detail = "missing wrap_hash"
		return check
	}
	if !evidence.CiphertextOverwritten || !evidence.ChipContributionDestroyed || !evidence.SaltRotated {
		check.Detail = "incomplete zeroization evidence"
		return check
	}
	check.OK = true
	check.Hash = truncateHex(stringsTrimPrefix(evidence.WrapHash, "sha256:"))
	check.Detail = "wrap erased, ciphertext overwritten, chip contribution destroyed, salt rotated"
	return check
}

func checkDestructionSaltEpoch(pkg map[string]any) Check {
	check := Check{ID: "salt_epoch", Label: "Salt Epoch"}
	switch v := pkg["salt_epoch"].(type) {
	case float64:
		if int(v) < 1 {
			check.Detail = "invalid salt_epoch"
			return check
		}
		check.OK = true
		check.Detail = fmt.Sprintf("epoch %d", int(v))
	case int:
		if v < 1 {
			check.Detail = "invalid salt_epoch"
			return check
		}
		check.OK = true
		check.Detail = fmt.Sprintf("epoch %d", v)
	default:
		check.Detail = "missing salt_epoch"
	}
	return check
}

func checkDestructionTenantHash(pkg map[string]any) Check {
	check := Check{ID: "destruction_tenant_hash", Label: "Tenant Hash"}
	hash, _ := pkg["tenant_id_hash"].(string)
	if hash == "" {
		check.Detail = "missing tenant_id_hash"
		return check
	}
	check.OK = true
	check.Hash = truncateHex(stringsTrimPrefix(hash, "sha256:"))
	check.Detail = hash
	return check
}

func checkUnifiedProof(proof destruction.Proof, receipts []destruction.Receipt) []Check {
	checks := []Check{}

	if err := destruction.VerifyProof(proof); err != nil {
		checks = append(checks, Check{ID: "proof_signature", Label: "Proof Signature", Detail: err.Error()})
	} else {
		checks = append(checks, Check{ID: "proof_signature", Label: "Proof Signature", OK: true, Detail: "substrate signature verified"})
	}

	quorum := proofQuorum(proof)
	if err := destruction.VerifyProofMerkle(proof, quorum, receipts); err != nil {
		checks = append(checks, Check{ID: "merkle_root", Label: "Merkle Root", Detail: err.Error()})
	} else {
		root, _ := proof.Package["merkle_root"].(string)
		checks = append(checks, Check{
			ID:     "merkle_root",
			Label:  "Merkle Root",
			OK:     true,
			Hash:   truncateHex(stringsTrimPrefix(root, "sha256:")),
			Detail: "receipt leaves recomputed to proof merkle_root",
		})
	}

	if proof.LogIndex == "" {
		checks = append(checks, Check{ID: "rekor_log_index", Label: "Rekor Log Index", Detail: "missing log_index (Rekor may be unreachable)"})
	} else {
		checks = append(checks, Check{
			ID:     "rekor_log_index",
			Label:  "Rekor Log Index",
			OK:     true,
			Detail: proof.LogIndex,
		})
	}
	return checks
}

func proofQuorum(proof destruction.Proof) []string {
	if proof.Package == nil {
		return nil
	}
	switch raw := proof.Package["quorum"].(type) {
	case []string:
		out := append([]string(nil), raw...)
		sort.Strings(out)
		return out
	case []any:
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	default:
		return nil
	}
}

func registryQuorum(registryURL, tenantID string) ([]string, error) {
	if registryURL == "" || tenantID == "" {
		return nil, fmt.Errorf("registry url and tenant id are required")
	}
	url := strings.TrimRight(registryURL, "/") + "/records/" + tenantID
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry %s", resp.Status)
	}
	var rec registry.CommitmentRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, err
	}
	ops := make([]string, 0, len(rec.Wraps))
	for op := range rec.Wraps {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	return ops, nil
}

func operatorIDs(receipts []destruction.Receipt) []string {
	ops := make([]string, 0, len(receipts))
	for _, r := range receipts {
		if op := r.OperatorID(); op != "" {
			ops = append(ops, op)
		}
	}
	sort.Strings(ops)
	return ops
}

func sameOperatorSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
