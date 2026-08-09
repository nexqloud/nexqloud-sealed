//go:build js && wasm

package tlog

import (
	"crypto/ed25519"
	"strings"
)

func AppendToLog(_ []byte, _ string, _ ed25519.PrivateKey) string {
	return ""
}

func AppendToLogAsync(pkgBytes []byte, sigHex string, priv ed25519.PrivateKey) {
	_ = AppendToLog(pkgBytes, strings.TrimSpace(sigHex), priv)
}
