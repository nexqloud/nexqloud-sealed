//go:build !(js && wasm)

package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"nexqloud-sealed/internal/devmode"
	"nexqloud-sealed/internal/enclave"
	"nexqloud-sealed/internal/gpu"
	"nexqloud-sealed/internal/tlog"
)

const (
	schemaVersion      = "sealed-receipt/1"
	placeholderMeasure = "41f77fe5c1416343f84dbeeded504eb4a2c450861317ed3e4e46cd771c794243a4cbeb3d75ec663e6a7a47bd1f4fab503"
	dummyModelCommit   = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	dummyIdentityClaim = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

type Input struct {
	Prompt             string
	Response           string
	ChallengeNonce     string
	IdentityClaimHash  string
}

type Builder struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func NewBuilder(priv ed25519.PrivateKey, pub ed25519.PublicKey) *Builder {
	return &Builder{priv: priv, pub: pub}
}

func (b *Builder) Seal(in Input) (*SealedReceipt, error) {
	nonce, nonceHex, err := resolveNonce(in.ChallengeNonce)
	if err != nil {
		return nil, err
	}

	policyHash, err := gpu.Hash(gpu.DefaultPolicy())
	if err != nil {
		return nil, err
	}

	att, err := enclave.RequestReport(b.pub, nonce)
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}

	measurement := ""
	if att != nil && att.Report != nil && len(att.Report.Measurement) > 0 {
		measurement = hex.EncodeToString(att.Report.Measurement)
	}
	if measurement == "" {
		if !devmode.Enabled() {
			return nil, fmt.Errorf("enclave measurement missing (set NEXQLOUD_DEV=1 for local fallback)")
		}
		measurement = placeholderMeasure
	}

	identityHash := in.IdentityClaimHash
	if identityHash == "" {
		if !devmode.Enabled() {
			return nil, fmt.Errorf("identity_claim_hash required (set NEXQLOUD_DEV=1 to allow placeholder)")
		}
		identityHash = dummyIdentityClaim
	}

	modelCommit, err := resolveModelCommitment()
	if err != nil {
		return nil, err
	}

	zeroCert, err := gpu.RequestZeroization()
	if err != nil {
		return nil, err
	}

	pkg := Package{
		Schema:             schemaVersion,
		ReceiptID:          uuid.NewString(),
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
		PromptHash:         digest(in.Prompt),
		ResponseHash:       digest(in.Response),
		ModelCommitment:    modelCommit,
		EnclaveMeasurement: measurement,
		GPUPolicyHash:      policyHash,
		ZeroizationCert:    zeroCert,
		IdentityClaimHash:  identityHash,
		Nonce:              nonceHex,
	}

	pkgMap, err := packageMap(pkg)
	if err != nil {
		return nil, err
	}

	canonicalPkg, err := Canonicalize(pkgMap)
	if err != nil {
		return nil, err
	}

	sig := ed25519.Sign(b.priv, canonicalPkg)
	sigHex := hex.EncodeToString(sig)

	tlog.AppendToLogAsync(canonicalPkg, sigHex, b.priv)

	attestationJSON, err := MarshalAttestation(att)
	if err != nil {
		return nil, err
	}

	certChain := EncodeCertificateChain(att.CertificateChain)
	if certChain.VCEK == "" {
		return nil, fmt.Errorf("attestation missing VCEK certificate")
	}

	return &SealedReceipt{
		Package:     pkg,
		Signature:   sigHex,
		Pubkey:      hex.EncodeToString(b.pub),
		Attestation: attestationJSON,
		CertChain:   certChain,
		LogIndex:    "",
	}, nil
}

func packageMap(pkg Package) (map[string]any, error) {
	raw, err := json.Marshal(pkg)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func resolveModelCommitment() (string, error) {
	if v := strings.TrimSpace(os.Getenv("NEXQLOUD_MODEL_COMMIT")); v != "" {
		return v, nil
	}
	if devmode.Enabled() {
		return dummyModelCommit, nil
	}
	return "", fmt.Errorf("NEXQLOUD_MODEL_COMMIT is required in production")
}
