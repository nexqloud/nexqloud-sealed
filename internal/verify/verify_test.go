package verify

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"testing"
	"github.com/google/go-sev-guest/proto/sevsnp"
)

func TestVerifyAzureKeyBinding(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	nonce := []byte("enclave-shim-nonce-12345678")
	expectedHash := sha512.Sum512(append(append([]byte{}, pub...), nonce...))
	expectedHex := hex.EncodeToString(expectedHash[:])

	claimsJSON := []byte(`{"keys":[],"vm-configuration":{},"user-data":"` + expectedHex + `"}`)

	rc := AttestationReceipt{
		Attestation: &sevsnp.Attestation{
			Report: &sevsnp.Report{ReportData: make([]byte, 64)},
		},
	}

	result := VerifyKeyBinding(rc, pub, Pins{Nonce: nonce}, claimsJSON)
	if !result.OK {
		t.Fatalf("expected success, got %q", result.Reason)
	}
}

func TestVerifyAzureWrapperBindingFails(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	nonce := []byte("nonce")
	claimsJSON := []byte(`{"keys":[],"vm-configuration":{},"user-data":"00"}`)

	reportData := make([]byte, 64)
	reportData[0] = 1

	rc := AttestationReceipt{
		Attestation: &sevsnp.Attestation{
			Report: &sevsnp.Report{ReportData: reportData},
		},
	}

	result := VerifyKeyBinding(rc, pub, Pins{Nonce: nonce}, claimsJSON)
	if result.OK || result.Reason != "azure-user-data-binding" {
		t.Fatalf("expected azure-user-data-binding, got %+v", result)
	}
}

func TestVerifyDirectKeyBinding(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	nonce := []byte("nonce")
	expectedHash := sha512.Sum512(append(append([]byte{}, pub...), nonce...))

	rc := AttestationReceipt{
		Attestation: &sevsnp.Attestation{
			Report: &sevsnp.Report{ReportData: expectedHash[:]},
		},
	}

	result := VerifyKeyBinding(rc, pub, Pins{Nonce: nonce}, nil)
	if !result.OK {
		t.Fatalf("expected success, got %q", result.Reason)
	}
}

func TestVerifyMissingVCEK(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	rc := AttestationReceipt{
		Attestation: &sevsnp.Attestation{
			Report: &sevsnp.Report{ReportData: make([]byte, 64)},
		},
	}

	result := Verify(rc, pub, Pins{Nonce: []byte("nonce")}, nil, HardwareRoots{})
	if result.OK || result.Reason != "missing-vcek" {
		t.Fatalf("expected missing-vcek, got %+v", result)
	}
}
