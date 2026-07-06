package destruction

import (
	"crypto/sha256"
	"encoding/hex"
)

func evidenceOf(wrap []byte) string {
	sum := sha256.Sum256(wrap)
	return "sha256:" + hex.EncodeToString(sum[:])
}
