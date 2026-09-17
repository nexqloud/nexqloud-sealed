package destruction

import (
	"crypto/ed25519"
	"encoding/hex"
	"time"

	"nexqloud-sealed/internal/receipt"
	"nexqloud-sealed/internal/tlog"
)

const DestructionMarkSchema = "sealed-destruction-mark/1"

// DestructionMark is the transparency-log entry for the anti-rollback step. It
// records that the federation salt was rolled for a tenant, which is what makes
// a later re-derivation of the destroyed DEK contradict the public log: the salt
// (and the epoch mixed into the HKDF salt) is no longer the one that produced
// the erased key.
type DestructionMark struct {
	Schema    string `json:"schema"`
	TenantID  string `json:"tenant_id"`
	SaltEpoch int    `json:"salt_epoch"`
	At        string `json:"at"`
}

func NewDestructionMark(tenantID string, saltEpoch int) DestructionMark {
	return DestructionMark{
		Schema:    DestructionMarkSchema,
		TenantID:  tenantID,
		SaltEpoch: saltEpoch,
		At:        time.Now().UTC().Format(time.RFC3339),
	}
}

// DestructionMarkPackage returns the RFC 8785 canonical bytes that are signed and
// published for a mark. Kept separate so the wire contract is testable without a
// transparency log.
func DestructionMarkPackage(mark DestructionMark) ([]byte, error) {
	return receipt.Canonicalize(map[string]any{
		"schema":     mark.Schema,
		"tenant_id":  mark.TenantID,
		"salt_epoch": mark.SaltEpoch,
		"at":         mark.At,
	})
}

// AppendDestructionMark signs the mark with the operator key and writes it to the
// transparency log, returning the Rekor log index. An empty index means the mark
// could not be published (no signer configured, or the log was unreachable); the
// destruction itself is already complete at that point, so callers report it
// rather than fail the erasure.
func AppendDestructionMark(signer ed25519.PrivateKey, mark DestructionMark) string {
	if len(signer) != ed25519.PrivateKeySize {
		return ""
	}
	canonical, err := DestructionMarkPackage(mark)
	if err != nil {
		return ""
	}
	sig := ed25519.Sign(signer, canonical)
	return tlog.AppendToLog(canonical, hex.EncodeToString(sig), signer)
}
