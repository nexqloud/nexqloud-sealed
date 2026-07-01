//go:build !(js && wasm)

package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/encoding/protojson"

	"nexqloud-sealed/internal/attest"
	"nexqloud-sealed/internal/tlog"
)

func DerivationReceipt(priv ed25519.PrivateKey, pub ed25519.PublicKey, opID string, att []byte, tenantID string, ver int, nonce []byte) map[string]any {
	return NewBuilder(priv, pub).DerivationReceipt(opID, att, tenantID, ver, nonce)
}

func (b *Builder) DerivationReceipt(opID string, attJSON []byte, tenantID string, ver int, nonce []byte) map[string]any {
	attHash, err := attest.ReportDigest(attJSON)
	if err != nil {
		panic(err)
	}

	pkg := map[string]any{
		"schema":           DerivationSchema,
		"operator_id":      opID,
		"attestation_hash": attHash,
		"tenant_id_hash":   digestBytes([]byte(tenantID)),
		"key_version":      ver,
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
	}

	canonicalPkg, err := Canonicalize(pkg)
	if err != nil {
		panic(err)
	}

	sig := ed25519.Sign(b.priv, canonicalPkg)
	sigHex := hex.EncodeToString(sig)

	logIndexCh := make(chan string, 1)
	go func() {
		logIndexCh <- tlog.AppendToLog(canonicalPkg, sigHex, b.priv)
	}()

	att := &sevsnp.Attestation{}
	if len(attJSON) > 0 {
		if err := protojson.Unmarshal(attJSON, att); err != nil {
			panic(err)
		}
	}

	certChain := EncodeCertificateChain(att.CertificateChain)

	runtimeClaimsJSON, err := AzureRuntimeClaims(b.pub, nonce)
	if err != nil {
		panic(err)
	}

	return map[string]any{
		"package":             pkg,
		"signature":           sigHex,
		"pubkey":              hex.EncodeToString(b.pub),
		"attestation":         json.RawMessage(attJSON),
		"cert_chain":          certChain,
		"runtime_claims_json": json.RawMessage(runtimeClaimsJSON),
		"nonce":               hex.EncodeToString(nonce),
		"log_index":           <-logIndexCh,
	}
}

func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
