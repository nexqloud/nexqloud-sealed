package kdf

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"strings"
)

// DEK input tracing, for diagnosing why a stored conversation cannot be reopened.
//
// Inert unless NEXQLOUD_DEK_TRACE is set to a non-empty value, so production behaviour
// and logs are unchanged by default. It prints fingerprints (sha256 prefixes and
// lengths) of the KDF inputs, never the inputs themselves: enough to tell which input
// changed between the call that sealed a conversation and the call that opens it, and
// nothing that could help someone reconstruct a key.
//
// Remove this file (and the two Trace* call sites) once the multi-turn bug is closed;
// or keep it, since it costs nothing when the variable is unset.

func TraceEnabled() bool {
	return strings.TrimSpace(os.Getenv("NEXQLOUD_DEK_TRACE")) != ""
}

func fp(b []byte) string {
	if len(b) == 0 {
		return "empty"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// TraceInputs logs the DEK inputs for one derivation.
func TraceInputs(stage string, seed, chipSecret, claimHash, attestBind []byte, tenantID string, version int) {
	if !TraceEnabled() {
		return
	}
	log.Printf("dek-trace[%s]: tenant=%s version=%d seed=%s/%d chip=%s/%d claim=%s/%d bind=%s/%d",
		stage, tenantID, version,
		fp(seed), len(seed),
		fp(chipSecret), len(chipSecret),
		fp(claimHash), len(claimHash),
		fp(attestBind), len(attestBind),
	)
}

// TraceIdentity logs which identity (tenant + claim digest) a derivation is bound to.
// This is what tells us whether two calls for the same conversation agree on the
// identity the DEK is derived from.
func TraceIdentity(stage, tenantID string, claimDigest []byte) {
	if !TraceEnabled() {
		return
	}
	log.Printf("dek-trace[%s]: identity tenant=%s claim=%s/%d", stage, tenantID, fp(claimDigest), len(claimDigest))
}
