//go:build !(js && wasm)

package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/google/go-sev-guest/proto/sevsnp"

	"nexqloud-sealed/internal/devmode"
	"nexqloud-sealed/internal/enclave"
	"nexqloud-sealed/internal/gpu"
	"nexqloud-sealed/internal/modelattest"
	"nexqloud-sealed/internal/tlog"
)

const (
	schemaVersion      = "sealed-receipt/1"
	placeholderMeasure = "41f77fe5c1416343f84dbeeded504eb4a2c450861317ed3e4e46cd771c794243a4cbeb3d75ec663e6a7a47bd1f4fab503"
	dummyIdentityClaim = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

type Input struct {
	Prompt            string
	Response          string
	ChallengeNonce    string
	IdentityClaimHash string
}

type Builder struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func NewBuilder(priv ed25519.PrivateKey, pub ed25519.PublicKey) *Builder {
	return &Builder{priv: priv, pub: pub}
}

// requestReport is the attestation seam. Both branches of the receipt's relationship
// with hardware only exist on one kind of machine — with SEV-SNP and without it — so a
// test that had to be run on one of them could never cover the other.
var requestReport = enclave.RequestReport

func (b *Builder) Seal(in Input) (*SealedReceipt, error) {
	nonce, nonceHex, err := resolveNonce(in.ChallengeNonce)
	if err != nil {
		return nil, err
	}

	policyHash, err := gpu.Hash(gpu.DefaultPolicy())
	if err != nil {
		return nil, err
	}

	// A dev fallback is only useful if it is reachable. Requesting the report is the
	// first thing that fails on a machine without SEV-SNP, so in dev mode the failure
	// becomes the placeholder below instead of ending the receipt: the measurement is
	// then the fixed dev constant, which is the marker a verifier sees.
	att, err := requestReport(b.pub, nonce)
	if err != nil {
		if !devmode.Enabled() {
			return nil, fmt.Errorf("attestation: %w", err)
		}
		att = nil
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

	modelCommit, modelCert, err := resolveModelCommitment(nonceHex)
	if err != nil {
		return nil, err
	}

	zeroCert, err := gpu.RequestZeroization(policyHash, nonceHex)
	if err != nil {
		return nil, err
	}

	pkg := Package{
		Schema:              schemaVersion,
		ReceiptID:           uuid.NewString(),
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		PromptHash:          digest(in.Prompt),
		ResponseHash:        digest(in.Response),
		ModelCommitment:     modelCommit,
		ModelCommitmentCert: modelCert,
		EnclaveMeasurement:  measurement,
		GPUPolicyHash:       policyHash,
		ZeroizationCert:     zeroCert,
		IdentityClaimHash:   identityHash,
		Nonce:               nonceHex,
		// A development receipt says so in the receipt itself. A verifier that does not
		// happen to know the placeholder measurement constant can still see that no
		// hardware attested this, instead of reading a signed package as proof.
		DevPlaceholder: measurement == placeholderMeasure,
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

	var chain *sevsnp.CertificateChain
	if att != nil {
		chain = att.CertificateChain
	}
	certChain := EncodeCertificateChain(chain)
	if certChain.VCEK == "" && !devmode.Enabled() {
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

func resolveModelCommitment(nonceHex string) (string, map[string]any, error) {
	return modelattest.RequestCommitment(nonceHex)
}
