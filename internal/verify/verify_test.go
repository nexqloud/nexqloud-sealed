package verify

import (
	"crypto/ed25519"
	"crypto/sha512"
	"testing"

	"github.com/google/go-sev-guest/proto/sevsnp"
)

func TestVerifyDirectKeyBinding(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	nonce := []byte("nonce")
	expectedHash := sha512.Sum512(append(append([]byte{}, pub...), nonce...))

	rc := AttestationReceipt{
		Attestation: &sevsnp.Attestation{
			Report: &sevsnp.Report{ReportData: expectedHash[:]},
		},
	}

	result := VerifyKeyBinding(rc, pub, Pins{Nonce: nonce})
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

	result := Verify(rc, pub, Pins{Nonce: []byte("nonce")}, HardwareRoots{})
	if result.OK || result.Reason != "missing-vcek" {
		t.Fatalf("expected missing-vcek, got %+v", result)
	}
}
