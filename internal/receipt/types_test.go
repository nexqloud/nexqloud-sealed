package receipt

import (
	"encoding/base64"
	"testing"

	"github.com/google/go-sev-guest/proto/sevsnp"
)

func TestCertificateChainRoundTrip(t *testing.T) {
	der := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
	encoded := EncodeCertificateChain(&sevsnp.CertificateChain{
		VcekCert: der,
		AskCert:  der,
		ArkCert:  der,
	})

	if encoded.VCEK != base64.StdEncoding.EncodeToString(der) {
		t.Fatalf("unexpected vcek encoding: %q", encoded.VCEK)
	}

	decoded, err := DecodeCertificateChain(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.VcekCert) != string(der) {
		t.Fatalf("vcek round trip failed")
	}
}

func TestDecodeCertificateChainMissingVCEK(t *testing.T) {
	_, err := DecodeCertificateChain(CertificateChain{})
	if err == nil {
		t.Fatal("expected error for missing vcek")
	}
}
