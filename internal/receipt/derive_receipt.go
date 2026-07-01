package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/gowebpki/jcs"
)

const derivationSchema = "sealed-derivation/1"

func DerivationReceipt(opID string, att []byte, tenantID string, ver int) map[string]any {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	pkg := map[string]any{
		"schema":           derivationSchema,
		"operator_id":      opID,
		"attestation_hash": hashBytes(att),
		"tenant_id_hash":   hashBytes([]byte(tenantID)),
		"key_version":      ver,
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
	}

	canonicalPkg, err := canonicalizeDerivation(pkg)
	if err != nil {
		panic(err)
	}

	sig := ed25519.Sign(priv, canonicalPkg)

	return map[string]any{
		"package":     pkg,
		"signature":   hex.EncodeToString(sig),
		"pubkey":      hex.EncodeToString(pub),
		"attestation": att,
		"log_index":   "0",
	}
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalizeDerivation(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}
