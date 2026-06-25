package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"

	"github.com/google/go-sev-guest/proto/sevsnp"

	"nexqloud-sealed/internal/receipt"
)

type AzureRuntimeClaims struct {
	Keys            json.RawMessage `json:"keys"`
	VMConfiguration json.RawMessage `json:"vm-configuration"`
	UserData        string          `json:"user-data"`
}

type Pins struct {
	Nonce              []byte
	EnclaveMeasurement string
	ModelCommitment    string
}

type AttestationReceipt struct {
	Attestation *sevsnp.Attestation
	CertChain   receipt.CertificateChain
}

type Result struct {
	OK     bool
	Reason string
}

func reportData(att *sevsnp.Attestation) []byte {
	if att == nil || att.Report == nil {
		return nil
	}
	return att.Report.ReportData
}

func fail(reason string) Result {
	return Result{OK: false, Reason: reason}
}

func ok() Result {
	return Result{OK: true}
}

func enclaveKeyHash(pub ed25519.PublicKey, nonce []byte) [64]byte {
	return sha512.Sum512(append(append([]byte{}, pub...), nonce...))
}

func Verify(rc AttestationReceipt, pub ed25519.PublicKey, pins Pins, azureClaimsJSON []byte, roots HardwareRoots) Result {
	if rc.Attestation == nil || rc.Attestation.Report == nil {
		return fail("missing-attestation")
	}

	if rc.CertChain.VCEK != "" {
		if result := VerifyHardwareChain(rc.Attestation, rc.CertChain, roots); !result.OK {
			return result
		}
	} else {
		return fail("missing-vcek")
	}

	return VerifyKeyBinding(rc, pub, pins, azureClaimsJSON)
}

func VerifyKeyBinding(rc AttestationReceipt, pub ed25519.PublicKey, pins Pins, azureClaimsJSON []byte) Result {
	if rc.Attestation == nil || rc.Attestation.Report == nil {
		return fail("missing-attestation")
	}

	if len(azureClaimsJSON) > 0 {
		return verifyAzureKeyBinding(rc, pub, pins, azureClaimsJSON)
	}

	expectedHash := enclaveKeyHash(pub, pins.Nonce)
	hwReportData := reportData(rc.Attestation)
	if !bytes.Equal(expectedHash[:], hwReportData) {
		return fail("key-binding")
	}

	return ok()
}

func verifyAzureKeyBinding(rc AttestationReceipt, pub ed25519.PublicKey, pins Pins, azureClaimsJSON []byte) Result {
	var claims AzureRuntimeClaims
	if err := json.Unmarshal(azureClaimsJSON, &claims); err != nil {
		return fail("azure-user-data-binding")
	}

	expectedHash := enclaveKeyHash(pub, pins.Nonce)
	expectedHex := hex.EncodeToString(expectedHash[:])
	if claims.UserData != expectedHex {
		return fail("azure-user-data-binding")
	}

	return ok()
}
