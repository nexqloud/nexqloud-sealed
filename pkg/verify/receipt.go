package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/gowebpki/jcs"
	"google.golang.org/protobuf/encoding/protojson"

	"nexqloud-sealed/internal/gpu"
	"nexqloud-sealed/internal/receipt"
	iv "nexqloud-sealed/internal/verify"
)

const (
	KnownEnclaveMeasurement = "41f77fe5c1416343f84dbeeded504eb4a2c450861317ed3e4e46cd771c79243a4cbeb3d75ec663e6a7a47bd1f4fab503"
)

var ModelCatalog = map[string]string{
	"mock-model": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
}

type Check struct {
	ID              string `json:"id"`
	Label           string `json:"label"`
	OK              bool   `json:"ok"`
	Detail          string `json:"detail"`
	Hash            string `json:"hash,omitempty"`
	ChainValidated  bool   `json:"chain_validated,omitempty"`
}

type ReceiptResult struct {
	OverallOK  bool    `json:"overall_ok"`
	Checks     []Check `json:"checks"`
	LogIndex   string  `json:"log_index"`
	ReceiptID  string  `json:"receipt_id"`
	Schema     string  `json:"schema,omitempty"`
	OperatorID string  `json:"operator_id,omitempty"`
	Error      string  `json:"error,omitempty"`
}

type ReceiptFile struct {
	Package           map[string]any           `json:"package"`
	Signature         string                   `json:"signature"`
	Pubkey            string                   `json:"pubkey"`
	Attestation       json.RawMessage          `json:"attestation"`
	CertChain         receipt.CertificateChain `json:"cert_chain"`
	RuntimeClaimsJSON json.RawMessage          `json:"runtime_claims_json"`
	Nonce             string                   `json:"nonce"`
	LogIndex          string                   `json:"log_index"`
}

func VerifyReceiptJSON(receiptJSON []byte, challengeHex string, rootsCatalog map[string]HardwareRoots) ReceiptResult {
	var wrapper ReceiptFile
	if err := json.Unmarshal(receiptJSON, &wrapper); err != nil {
		return ReceiptResult{Error: fmt.Sprintf("parse receipt: %v", err)}
	}
	return VerifyReceipt(wrapper, challengeHex, rootsCatalog)
}

func packageSchema(pkg map[string]any) string {
	if pkg == nil {
		return ""
	}
	schema, _ := pkg["schema"].(string)
	return schema
}

func VerifyReceipt(wrapper ReceiptFile, challengeHex string, rootsCatalog map[string]HardwareRoots) ReceiptResult {
	if packageSchema(wrapper.Package) == receipt.DerivationSchema {
		return verifyDerivationReceipt(wrapper, challengeHex, rootsCatalog)
	}
	return verifyInferenceReceipt(wrapper, challengeHex, rootsCatalog)
}

func verifyInferenceReceipt(wrapper ReceiptFile, challengeHex string, rootsCatalog map[string]HardwareRoots) ReceiptResult {
	result := ReceiptResult{
		LogIndex: wrapper.LogIndex,
	}

	if wrapper.Package == nil {
		result.Error = "missing package"
		return result
	}

	if id, ok := wrapper.Package["receipt_id"].(string); ok {
		result.ReceiptID = id
	}

	pub, err := hex.DecodeString(wrapper.Pubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		result.Error = "invalid pubkey"
		return result
	}
	publicKey := ed25519.PublicKey(pub)

	nonceHex, _ := wrapper.Package["nonce"].(string)
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != 32 {
		result.Error = "invalid nonce"
		return result
	}

	att := &sevsnp.Attestation{}
	if len(wrapper.Attestation) > 0 && string(wrapper.Attestation) != "{}" {
		if err := protojson.Unmarshal(wrapper.Attestation, att); err != nil {
			result.Error = fmt.Sprintf("parse attestation: %v", err)
			return result
		}
	}

	roots := pickHardwareRoots(att, rootsCatalog)

	result.Checks = append(result.Checks,
		checkSignature(wrapper, publicKey),
		checkHardware(att, wrapper.CertChain, roots),
		checkKeyBinding(att, wrapper.CertChain, publicKey, nonce, wrapper.RuntimeClaimsJSON),
		checkCodeLegit(wrapper.Package),
		checkModelLegit(wrapper.Package),
		checkGPUWiped(wrapper.Package),
		checkFreshness(nonceHex, challengeHex),
	)

	result.OverallOK = true
	for _, c := range result.Checks {
		if !c.OK {
			result.OverallOK = false
			break
		}
	}

	return result
}

func verifyDerivationReceipt(wrapper ReceiptFile, challengeHex string, rootsCatalog map[string]HardwareRoots) ReceiptResult {
	result := ReceiptResult{
		LogIndex: wrapper.LogIndex,
		Schema:   receipt.DerivationSchema,
	}

	if wrapper.Package == nil {
		result.Error = "missing package"
		return result
	}

	if opID, ok := wrapper.Package["operator_id"].(string); ok {
		result.OperatorID = opID
	}

	pub, err := hex.DecodeString(wrapper.Pubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		result.Error = "invalid pubkey"
		return result
	}
	publicKey := ed25519.PublicKey(pub)

	nonceHex := wrapper.Nonce
	if nonceHex == "" {
		nonceHex, _ = wrapper.Package["nonce"].(string)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != 32 {
		result.Error = "invalid nonce"
		return result
	}

	att := &sevsnp.Attestation{}
	if len(wrapper.Attestation) > 0 && string(wrapper.Attestation) != "{}" {
		if err := protojson.Unmarshal(wrapper.Attestation, att); err != nil {
			result.Error = fmt.Sprintf("parse attestation: %v", err)
			return result
		}
	}

	chain := resolveCertChain(wrapper.CertChain, att)
	roots := pickHardwareRoots(att, rootsCatalog)

	result.Checks = append(result.Checks,
		checkSignature(wrapper, publicKey),
		checkHardware(att, chain, roots),
		checkKeyBinding(att, chain, publicKey, nonce, wrapper.RuntimeClaimsJSON),
		checkDerivationAttestationHash(wrapper.Package, wrapper.Attestation),
		checkDerivationOperatorID(wrapper.Package),
		checkDerivationKeyVersion(wrapper.Package),
		checkDerivationTenantHash(wrapper.Package),
	)

	result.OverallOK = true
	for _, c := range result.Checks {
		if !c.OK {
			result.OverallOK = false
			break
		}
	}

	return result
}

func resolveCertChain(chain receipt.CertificateChain, att *sevsnp.Attestation) receipt.CertificateChain {
	if chain.VCEK != "" {
		return chain
	}
	if att != nil && att.CertificateChain != nil {
		return receipt.EncodeCertificateChain(att.CertificateChain)
	}
	return chain
}

func checkDerivationAttestationHash(pkg map[string]any, attRaw json.RawMessage) Check {
	check := Check{
		ID:    "derivation_attestation_hash",
		Label: "Attestation Hash",
	}

	expected, _ := pkg["attestation_hash"].(string)
	check.Hash = truncateHex(stringsTrimPrefix(expected, "sha256:"))
	if expected == "" {
		check.Detail = "missing attestation_hash"
		return check
	}

	sum, err := attestationProtoDigest(attRaw)
	if err != nil {
		check.Detail = err.Error()
		return check
	}
	actual := "sha256:" + hex.EncodeToString(sum)
	if actual == expected {
		check.OK = true
		check.Detail = "attestation bytes match package hash"
	} else {
		check.Detail = "attestation_hash mismatch"
	}
	return check
}

func checkDerivationOperatorID(pkg map[string]any) Check {
	check := Check{
		ID:    "derivation_operator_id",
		Label: "Operator ID",
	}
	opID, _ := pkg["operator_id"].(string)
	if opID == "" {
		check.Detail = "missing operator_id"
		return check
	}
	check.OK = true
	check.Hash = truncateHex(opID)
	check.Detail = opID
	return check
}

func checkDerivationKeyVersion(pkg map[string]any) Check {
	check := Check{
		ID:    "derivation_key_version",
		Label: "Key Version",
	}
	version, ok := pkg["key_version"].(float64)
	if !ok || version <= 0 {
		check.Detail = "missing or invalid key_version"
		return check
	}
	check.OK = true
	check.Detail = fmt.Sprintf("v%d", int(version))
	return check
}

func checkDerivationTenantHash(pkg map[string]any) Check {
	check := Check{
		ID:    "derivation_tenant_hash",
		Label: "Tenant ID Hash",
	}
	tenantHash, _ := pkg["tenant_id_hash"].(string)
	if tenantHash == "" || !stringsHasPrefix(tenantHash, "sha256:") {
		check.Detail = "missing or invalid tenant_id_hash"
		return check
	}
	check.OK = true
	check.Hash = truncateHex(stringsTrimPrefix(tenantHash, "sha256:"))
	check.Detail = tenantHash
	return check
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func attestationProtoDigest(attRaw json.RawMessage) ([]byte, error) {
	if len(attRaw) == 0 || string(attRaw) == "{}" {
		return nil, fmt.Errorf("missing attestation")
	}

	att := &sevsnp.Attestation{}
	if err := protojson.Unmarshal(attRaw, att); err != nil {
		return nil, fmt.Errorf("parse attestation: %w", err)
	}

	canonical, err := protojson.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("marshal attestation: %w", err)
	}

	sum := sha256.Sum256(canonical)
	return sum[:], nil
}

func pickHardwareRoots(att *sevsnp.Attestation, catalog map[string]HardwareRoots) iv.HardwareRoots {
	if catalog == nil {
		return iv.HardwareRoots{}
	}
	productLine, err := iv.ProductLineFromReport(att)
	if err != nil {
		return iv.HardwareRoots{}
	}
	if roots, ok := catalog[productLine]; ok {
		return roots.internal()
	}
	return iv.HardwareRoots{ProductLine: productLine}
}

func checkSignature(wrapper ReceiptFile, pub ed25519.PublicKey) Check {
	check := Check{
		ID:    "signature_valid",
		Label: "Signature Valid",
	}

	sig, err := hex.DecodeString(wrapper.Signature)
	if err != nil {
		check.Detail = "invalid signature encoding"
		return check
	}

	canonical, err := canonicalizePackage(wrapper.Package)
	if err != nil {
		check.Detail = err.Error()
		return check
	}

	check.Hash = truncateHex(wrapper.Signature)
	if ed25519.Verify(pub, canonical, sig) {
		check.OK = true
		check.Detail = "ed25519 over RFC 8785 canonical package"
	} else {
		check.Detail = "ed25519 verification failed"
	}
	return check
}

func checkHardware(att *sevsnp.Attestation, chain receipt.CertificateChain, roots iv.HardwareRoots) Check {
	check := Check{
		ID:    "hardware_genuine",
		Label: "Hardware Genuine",
	}

	if att == nil || att.Report == nil {
		check.Detail = "missing attestation report"
		return check
	}

	if att.Report.ChipId != nil {
		check.Hash = truncateHex(hex.EncodeToString(att.Report.ChipId))
	}

	if chain.VCEK == "" {
		check.Detail = "missing VCEK certificate"
		return check
	}

	result := iv.VerifyHardwareChain(att, chain, roots)
	check.OK = result.OK
	check.ChainValidated = result.OK
	if result.OK {
		check.Detail = "Full chain verified: VCEK → ASK → ARK matched to AMD Root"
	} else {
		check.Detail = result.Reason
	}
	return check
}

func checkKeyBinding(att *sevsnp.Attestation, chain receipt.CertificateChain, pub ed25519.PublicKey, nonce []byte, azureClaimsJSON []byte) Check {
	check := Check{
		ID:    "key_binding",
		Label: "Key Bound to Silicon",
	}

	expectedHash := enclaveKeyHash(pub, nonce)
	check.Hash = truncateHex(hex.EncodeToString(expectedHash[:]))

	rc := iv.AttestationReceipt{Attestation: att, CertChain: chain}
	result := iv.VerifyKeyBinding(rc, pub, iv.Pins{Nonce: nonce}, azureClaimsJSON)
	if result.OK {
		check.OK = true
		check.Detail = "REPORT_DATA match"
		if att != nil && att.Report != nil && len(att.Report.ReportData) > 0 {
			check.Hash = truncateHex(hex.EncodeToString(att.Report.ReportData))
		}
	} else {
		check.Detail = result.Reason
	}
	return check
}

func enclaveKeyHash(pub ed25519.PublicKey, nonce []byte) [64]byte {
	return sha512.Sum512(append(append([]byte{}, pub...), nonce...))
}

func checkCodeLegit(pkg map[string]any) Check {
	check := Check{
		ID:    "code_legit",
		Label: "Code Legit",
	}

	measurement, _ := pkg["enclave_measurement"].(string)
	check.Hash = truncateHex(measurement)

	if measurement != KnownEnclaveMeasurement {
		check.Detail = "enclave_measurement mismatch"
		return check
	}

	check.OK = true
	check.Detail = "measurement: " + truncateHex(measurement)
	return check
}

func checkModelLegit(pkg map[string]any) Check {
	check := Check{
		ID:    "model_legit",
		Label: "Model Legit",
	}

	commitment, _ := pkg["model_commitment"].(string)
	check.Hash = truncateHex(stringsTrimPrefix(commitment, "sha256:"))

	for _, catalogHash := range ModelCatalog {
		if commitment == catalogHash {
			check.OK = true
			check.Detail = commitment
			return check
		}
	}

	check.Detail = "model_commitment not in catalog"
	return check
}

func checkGPUWiped(pkg map[string]any) Check {
	check := Check{
		ID:    "gpu_wiped",
		Label: "GPU Wiped",
	}

	policyHash, _ := pkg["gpu_policy_hash"].(string)
	expectedHash, err := gpu.Hash(gpu.DefaultPolicy())
	if err != nil {
		check.Detail = err.Error()
		return check
	}

	check.Hash = truncateHex(stringsTrimPrefix(policyHash, "sha256:"))
	if policyHash != expectedHash {
		check.Detail = "gpu_policy_hash mismatch"
		return check
	}

	certRaw, ok := pkg["zeroization_cert"].(map[string]any)
	if !ok {
		check.Detail = "missing zeroization_cert"
		return check
	}

	mock := gpu.RequestZeroization()
	for _, key := range []string{"clearance_id", "gpu_id", "wiped_at", "signature", "issuer"} {
		if certRaw[key] == nil || certRaw[key] == "" {
			check.Detail = fmt.Sprintf("zeroization_cert missing %s", key)
			return check
		}
		if mock[key] != certRaw[key] {
			check.Detail = fmt.Sprintf("zeroization_cert %s mismatch", key)
			return check
		}
	}

	check.OK = true
	check.Detail = "policy enforced"
	return check
}

func checkFreshness(nonceHex, challengeHex string) Check {
	check := Check{
		ID:    "freshness",
		Label: "Freshness",
		Hash:  truncateHex(nonceHex),
	}

	if challengeHex == "" {
		check.OK = true
		check.Detail = "nonce present (no challenge supplied)"
		return check
	}

	challenge, err := hex.DecodeString(challengeHex)
	if err != nil {
		check.Detail = "invalid challenge encoding"
		return check
	}

	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		check.Detail = "invalid nonce encoding"
		return check
	}

	if bytes.Equal(nonce, challenge) {
		check.OK = true
		check.Detail = "nonce matches challenge"
	} else {
		check.Detail = "nonce does not match challenge"
	}
	return check
}

func canonicalizePackage(pkg map[string]any) ([]byte, error) {
	raw, err := json.Marshal(pkg)
	if err != nil {
		return nil, fmt.Errorf("marshal package: %w", err)
	}
	return jcs.Transform(raw)
}

func truncateHex(s string) string {
	s = stringsTrimPrefix(s, "sha256:")
	if len(s) <= 16 {
		return s
	}
	return s[:8] + "…" + s[len(s)-8:]
}

func stringsTrimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}
