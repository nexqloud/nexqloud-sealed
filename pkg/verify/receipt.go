package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/gowebpki/jcs"
	"google.golang.org/protobuf/encoding/protojson"

	"nexqloud-sealed/internal/attest"
	"nexqloud-sealed/internal/gpu"
	"nexqloud-sealed/internal/modelattest"
	"nexqloud-sealed/internal/receipt"
	iv "nexqloud-sealed/internal/verify"
)

type Check struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	OK             bool   `json:"ok"`
	Detail         string `json:"detail"`
	Hash           string `json:"hash,omitempty"`
	ChainValidated bool   `json:"chain_validated,omitempty"`
	// Source is a debug hint for which verification path produced this check
	// (e.g. code_legit: "sigstore_proof", "published_catalog").
	Source string `json:"source,omitempty"`
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
	Package     map[string]any           `json:"package"`
	Signature   string                   `json:"signature"`
	Pubkey      string                   `json:"pubkey"`
	Attestation json.RawMessage          `json:"attestation"`
	CertChain   receipt.CertificateChain `json:"cert_chain"`
	Nonce       string                   `json:"nonce"`
	LogIndex    string                   `json:"log_index"`
}

func VerifyReceiptJSON(receiptJSON []byte, challengeHex string, rootsCatalog map[string]HardwareRoots) ReceiptResult {
	return VerifyReceiptJSONOpts(receiptJSON, VerifyOpts{
		ChallengeHex: challengeHex,
		RootsCatalog: rootsCatalog,
	})
}

// VerifyOpts configures receipt verification.
//
// Code Legit (Pattern 1): when MeasurementProofs is non-empty, the launch
// measurement must match a proof whose cosign/Sigstore bundle verifies under
// the sealed-initrd workflow identity. Otherwise Measurements must contain the
// launch measurement hex from the published R2 allowlist (no embedded catalog).
//
// Model Legit: Models is the published model_commitment allowlist. ModelAttestIssuers
// are ed25519 pubkey hex values allowed to sign model_commitment_cert.
//
// GPU Wiped: GPUPolicyHashes, WipeIssuers (ed25519 pubkey hex), and WipeWorkers
// (worker binary sha256 commitments) come from published allowlists.
type VerifyOpts struct {
	ChallengeHex        string
	RootsCatalog        map[string]HardwareRoots
	Measurements        []string
	MeasurementProofs   []MeasurementProof
	Models              []string
	ModelAttestIssuers  []string
	GPUPolicyHashes     []string
	WipeIssuers         []string
	WipeWorkers         []string
	AllowDevNoop        bool
}

func VerifyReceiptJSONOpts(receiptJSON []byte, opts VerifyOpts) ReceiptResult {
	var wrapper ReceiptFile
	if err := json.Unmarshal(receiptJSON, &wrapper); err != nil {
		return ReceiptResult{Error: fmt.Sprintf("parse receipt: %v", err)}
	}
	return VerifyReceiptOpts(wrapper, opts)
}

func packageSchema(pkg map[string]any) string {
	if pkg == nil {
		return ""
	}
	schema, _ := pkg["schema"].(string)
	return schema
}

func VerifyReceipt(wrapper ReceiptFile, challengeHex string, rootsCatalog map[string]HardwareRoots) ReceiptResult {
	return VerifyReceiptOpts(wrapper, VerifyOpts{
		ChallengeHex: challengeHex,
		RootsCatalog: rootsCatalog,
	})
}

func VerifyReceiptOpts(wrapper ReceiptFile, opts VerifyOpts) ReceiptResult {
	if packageSchema(wrapper.Package) == receipt.DerivationSchema {
		return verifyDerivationReceipt(wrapper, opts.ChallengeHex, opts.RootsCatalog)
	}
	return verifyInferenceReceipt(wrapper, opts)
}

func verifyInferenceReceipt(wrapper ReceiptFile, opts VerifyOpts) ReceiptResult {
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

	roots := pickHardwareRoots(att, opts.RootsCatalog)

	result.Checks = append(result.Checks,
		checkSignature(wrapper, publicKey),
		checkHardware(att, wrapper.CertChain, roots),
		checkKeyBinding(att, wrapper.CertChain, publicKey, nonce),
		checkCodeLegit(wrapper.Package, att, opts),
		checkModelLegit(wrapper.Package, opts),
		checkGPUWiped(wrapper.Package, opts),
		checkFreshness(nonceHex, opts.ChallengeHex),
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

	roots := pickHardwareRoots(att, rootsCatalog)

	result.Checks = append(result.Checks,
		checkSignature(wrapper, publicKey),
		checkHardware(att, wrapper.CertChain, roots),
		checkKeyBinding(att, wrapper.CertChain, publicKey, nonce),
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
	digest, err := attest.ReportDigest(attRaw)
	if err != nil {
		return nil, err
	}
	const prefix = "sha256:"
	if len(digest) <= len(prefix) || digest[:len(prefix)] != prefix {
		return nil, fmt.Errorf("invalid digest: %s", digest)
	}
	sum, err := hex.DecodeString(digest[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("decode digest: %w", err)
	}
	return sum, nil
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
		check.Detail = "Receipt package is intact and signed by the enclave key"
	} else {
		check.Detail = "Signature does not match the package"
	}
	return check
}

func checkHardware(att *sevsnp.Attestation, chain receipt.CertificateChain, roots iv.HardwareRoots) Check {
	check := Check{
		ID:    "hardware_genuine",
		Label: "Real AMD Hardware",
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
		check.Detail = "Attestation came from real AMD SEV-SNP hardware with a valid AMD certificate chain"
	} else {
		check.Detail = result.Reason
	}
	return check
}

func checkKeyBinding(att *sevsnp.Attestation, chain receipt.CertificateChain, pub ed25519.PublicKey, nonce []byte) Check {
	check := Check{
		ID:    "key_binding",
		Label: "Signing Key Bound to Hardware",
	}

	expectedHash := enclaveKeyHash(pub, nonce)
	check.Hash = truncateHex(hex.EncodeToString(expectedHash[:]))

	rc := iv.AttestationReceipt{Attestation: att, CertChain: chain}
	result := iv.VerifyKeyBinding(rc, pub, iv.Pins{Nonce: nonce})
	if result.OK {
		check.OK = true
		check.Detail = "Signing key is bound into this AMD hardware attestation for this session"
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

func checkCodeLegit(pkg map[string]any, att *sevsnp.Attestation, opts VerifyOpts) Check {
	check := Check{
		ID:    "code_legit",
		Label: "Approved Enclave Code",
	}

	pkgMeas, _ := pkg["enclave_measurement"].(string)
	pkgMeas = strings.ToLower(strings.TrimSpace(pkgMeas))
	reportMeas := ""
	if att != nil && att.Report != nil && len(att.Report.Measurement) > 0 {
		reportMeas = hex.EncodeToString(att.Report.Measurement)
	}

	if reportMeas != "" && pkgMeas != "" && reportMeas != pkgMeas {
		check.Hash = truncateHex(reportMeas)
		check.Detail = "package enclave_measurement != attestation MEASUREMENT"
		check.Source = "mismatch"
		slog.Info("code_legit", "path", check.Source, "ok", false)
		return check
	}

	candidate := reportMeas
	if candidate == "" {
		candidate = pkgMeas
	}
	if candidate == "" {
		check.Detail = "missing launch measurement"
		check.Source = "missing"
		slog.Info("code_legit", "path", check.Source, "ok", false)
		return check
	}
	check.Hash = truncateHex(candidate)

	if n := len(opts.MeasurementProofs); n > 0 {
		slog.Debug("code_legit", "step", "trying_sigstore_proof", "proofs", n, "measurement", truncateHex(candidate))
		var lastErr error
		for i, proof := range opts.MeasurementProofs {
			if err := VerifyCosignBlobBundle(proof.PayloadBytes(), proof.BundleJSON); err != nil {
				lastErr = err
				slog.Debug("code_legit", "step", "sigstore_proof", "proof", i, "err", err)
				continue
			}
			if MeasurementFromPayload(proof.PayloadBytes()) != candidate {
				slog.Debug("code_legit", "step", "sigstore_proof", "proof", i, "mismatch_git", truncateHex(proof.GitSHA))
				continue
			}
			check.OK = true
			check.Source = "sigstore_proof"
			check.Detail = "Enclave code matches a NexQloud-published build with a valid CI transparency-log proof"
			slog.Info("code_legit", "path", check.Source, "ok", true, "git", truncateHex(proof.GitSHA), "env", proof.Environment)
			return check
		}
		if lastErr != nil {
			check.Detail = "no valid Sigstore proof for launch measurement: " + lastErr.Error()
		} else {
			check.Detail = "no Sigstore proof matched launch measurement"
		}
		check.Source = "sigstore_proof"
		slog.Info("code_legit", "path", check.Source, "ok", false)
		return check
	}

	catalog := EffectiveMeasurements(opts.Measurements)
	if len(catalog) == 0 {
		check.Source = "missing_allowlist"
		check.Detail = "no Sigstore proof or published allowlist for launch measurement"
		slog.Info("code_legit", "path", check.Source, "ok", false)
		return check
	}
	slog.Debug("code_legit", "step", "trying_published_catalog", "catalog_size", len(catalog), "measurement", truncateHex(candidate))

	for _, known := range catalog {
		if candidate == strings.ToLower(strings.TrimSpace(known)) {
			check.OK = true
			check.Source = "published_catalog"
			check.Detail = "Enclave code matches a measurement on the NexQloud published allowlist"
			slog.Info("code_legit", "path", check.Source, "ok", true)
			return check
		}
	}

	check.Source = "published_catalog"
	check.Detail = "launch measurement not on published allowlist"
	slog.Info("code_legit", "path", check.Source, "ok", false)
	return check
}

func checkModelLegit(pkg map[string]any, opts VerifyOpts) Check {
	check := Check{
		ID:    "model_legit",
		Label: "Approved Model",
	}

	commitment, _ := pkg["model_commitment"].(string)
	check.Hash = truncateHex(stringsTrimPrefix(commitment, "sha256:"))
	if commitment == "" {
		check.Detail = "missing model_commitment"
		return check
	}

	certRaw, ok := pkg["model_commitment_cert"].(map[string]any)
	if !ok {
		check.Detail = "missing model_commitment_cert"
		return check
	}
	cert, err := modelattest.CertFromMap(certRaw)
	if err != nil {
		check.Detail = err.Error()
		return check
	}
	if err := modelattest.VerifyCertSignature(cert); err != nil {
		check.Detail = err.Error()
		return check
	}
	nonceHex, _ := pkg["nonce"].(string)
	if cert.Nonce == "" || nonceHex == "" || cert.Nonce != nonceHex {
		check.Detail = "model_commitment_cert.nonce mismatch"
		return check
	}
	if cert.ModelCommitment != commitment {
		check.Detail = "model_commitment_cert.model_commitment mismatch"
		return check
	}

	issuers := EffectiveModelAttestIssuers(opts.ModelAttestIssuers)
	if len(issuers) == 0 {
		check.Detail = "model attest issuer allowlist empty"
		return check
	}
	pub := strings.ToLower(strings.TrimSpace(cert.Pubkey))
	issuerOK := false
	for _, want := range issuers {
		if pub == strings.ToLower(strings.TrimSpace(want)) {
			issuerOK = true
			break
		}
	}
	if !issuerOK {
		check.Detail = "model_commitment_cert pubkey not in issuer allowlist"
		return check
	}

	for _, catalogHash := range EffectiveModelCommitments(opts.Models) {
		if commitment == catalogHash {
			check.OK = true
			check.Detail = "Model weights match a NexQloud-published model commitment"
			return check
		}
	}

	check.Detail = "model_commitment not in catalog"
	return check
}

func checkGPUWiped(pkg map[string]any, opts VerifyOpts) Check {
	check := Check{
		ID:    "gpu_wiped",
		Label: "GPU Wiped",
	}

	policyHash, _ := pkg["gpu_policy_hash"].(string)
	check.Hash = truncateHex(stringsTrimPrefix(policyHash, "sha256:"))

	policyCatalog := EffectiveGPUPolicyHashes(opts.GPUPolicyHashes)
	if len(policyCatalog) == 0 {
		check.Detail = "gpu policy allowlist empty"
		return check
	}
	matched := false
	for _, expectedHash := range policyCatalog {
		if policyHash == expectedHash {
			matched = true
			break
		}
	}
	if !matched {
		check.Detail = "gpu_policy_hash not in allowlist"
		return check
	}

	certRaw, ok := pkg["zeroization_cert"].(map[string]any)
	if !ok {
		check.Detail = "missing zeroization_cert"
		return check
	}

	cert, err := gpu.CertFromMap(certRaw)
	if err != nil {
		check.Detail = err.Error()
		return check
	}
	if err := gpu.VerifyCertSignature(cert); err != nil {
		check.Detail = err.Error()
		return check
	}
	if cert.PolicyHash != policyHash {
		check.Detail = "zeroization_cert.policy_hash mismatch"
		return check
	}
	nonceHex, _ := pkg["nonce"].(string)
	if cert.Nonce != "" && nonceHex != "" && cert.Nonce != nonceHex {
		check.Detail = "zeroization_cert.nonce mismatch"
		return check
	}
	switch cert.Method {
	case gpu.MethodTwoPass:
	case gpu.MethodDevNoop:
		if !opts.AllowDevNoop {
			check.Detail = "dev-noop wipe method not allowed"
			return check
		}
	default:
		check.Detail = fmt.Sprintf("unsupported wipe method %q", cert.Method)
		return check
	}
	if err := gpu.ValidateCertTimestamp(cert, time.Now().UTC(), 5*time.Minute); err != nil {
		check.Detail = err.Error()
		return check
	}

	issuers := EffectiveWipeIssuers(opts.WipeIssuers)
	if len(issuers) == 0 {
		check.Detail = "wipe issuer allowlist empty"
		return check
	}
	pub := strings.ToLower(strings.TrimSpace(cert.Pubkey))
	issuerOK := false
	for _, want := range issuers {
		if pub == strings.ToLower(strings.TrimSpace(want)) {
			issuerOK = true
			break
		}
	}
	if !issuerOK {
		check.Detail = "wipe issuer pubkey not in allowlist"
		return check
	}

	workers := EffectiveWipeWorkers(opts.WipeWorkers)
	if len(workers) == 0 {
		check.Detail = "wipe worker allowlist empty"
		return check
	}
	wc := strings.TrimSpace(cert.WorkerCommitment)
	if wc == "" {
		check.Detail = "zeroization_cert missing worker_commitment"
		return check
	}
	workerOK := false
	for _, want := range workers {
		if wc == strings.TrimSpace(want) {
			workerOK = true
			break
		}
	}
	if !workerOK {
		check.Detail = "worker_commitment not in allowlist"
		return check
	}

	check.OK = true
	check.Detail = "two-pass wipe cert verified"
	if cert.Method == gpu.MethodDevNoop {
		check.Detail = "dev-noop wipe cert verified"
	}
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
