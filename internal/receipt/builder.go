//go:build !(js && wasm)

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/gowebpki/jcs"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/encoding/protojson"

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
	Prompt   string
	Response string
}

type Builder struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func NewBuilder(priv ed25519.PrivateKey, pub ed25519.PublicKey) *Builder {
	return &Builder{priv: priv, pub: pub}
}

func (b *Builder) Seal(in Input) (*SealedReceipt, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	policyHash, err := gpu.Hash(gpu.DefaultPolicy())
	if err != nil {
		return nil, err
	}

	runtimeClaimsJSON, err := buildAzureRuntimeClaims(b.pub, nonce)
	if err != nil {
		return nil, err
	}

	att, err := enclave.RequestReport(b.pub, nonce)
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}

	measurement := placeholderMeasure
	if att != nil && att.Report != nil && len(att.Report.Measurement) > 0 {
		measurement = hex.EncodeToString(att.Report.Measurement)
	}

	pkg := Package{
		Schema:             schemaVersion,
		ReceiptID:          uuid.NewString(),
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
		PromptHash:         digest(in.Prompt),
		ResponseHash:       digest(in.Response),
		ModelCommitment:    dummyModelCommit,
		EnclaveMeasurement: measurement,
		GPUPolicyHash:      policyHash,
		ZeroizationCert:    gpu.RequestZeroization(),
		IdentityClaimHash:  dummyIdentityClaim,
		Nonce:              hex.EncodeToString(nonce),
	}

	pkgMap, err := packageMap(pkg)
	if err != nil {
		return nil, err
	}

	canonicalPkg, err := canonicalize(pkgMap)
	if err != nil {
		return nil, err
	}

	sig := ed25519.Sign(b.priv, canonicalPkg)
	sigHex := hex.EncodeToString(sig)

	logIndexCh := make(chan string, 1)
	go func() {
		logIndexCh <- tlog.AppendToLog(canonicalPkg, sigHex, b.priv)
	}()

	attestationJSON, err := attestationJSON(att)
	if err != nil {
		return nil, err
	}

	certChain := EncodeCertificateChain(att.CertificateChain)
	if certChain.VCEK == "" {
		return nil, fmt.Errorf("attestation missing VCEK certificate")
	}

	return &SealedReceipt{
		Package:           pkg,
		Signature:         sigHex,
		Pubkey:            hex.EncodeToString(b.pub),
		Attestation:       attestationJSON,
		CertChain:         certChain,
		RuntimeClaimsJSON: json.RawMessage(runtimeClaimsJSON),
		LogIndex:          <-logIndexCh,
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

func canonicalize(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

func buildAzureRuntimeClaims(pub ed25519.PublicKey, nonce []byte) ([]byte, error) {
	keyHash := enclave.KeyHash(pub, nonce)
	userData := hex.EncodeToString(keyHash[:])
	claims := map[string]any{
		"keys":             []any{},
		"vm-configuration": map[string]any{},
		"user-data":        userData,
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

func attestationJSON(att *sevsnp.Attestation) (json.RawMessage, error) {
	if att == nil {
		return json.RawMessage("{}"), nil
	}
	raw, err := protojson.Marshal(att)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}
