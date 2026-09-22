package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-sev-guest/proto/sevsnp"
)

// A machine either has SEV-SNP or it does not, and the receipt's behaviour has to be
// right on both. These tests replace the attestation seam so both branches run here.
func TestSealWithoutHardwareAttestation(t *testing.T) {
	priv, pub := newKey(t)
	saved := requestReport
	defer func() { requestReport = saved }()
	requestReport = func(ed25519.PublicKey, []byte) (*sevsnp.Attestation, error) {
		return nil, errors.New("no supported SEV-SNP QuoteProvider found")
	}

	t.Run("in dev mode the receipt is minted and says it is a placeholder", func(t *testing.T) {
		t.Setenv("NEXQLOUD_DEV", "1")

		sealed, err := NewBuilder(priv, pub).Seal(Input{Prompt: "p", Response: "r"})
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if !sealed.Package.DevPlaceholder {
			t.Fatal("a receipt with no hardware attestation was not marked as a placeholder")
		}
		if sealed.Package.EnclaveMeasurement != placeholderMeasure {
			t.Fatalf("measurement = %q, want the dev placeholder", sealed.Package.EnclaveMeasurement)
		}
		if sealed.Package.IdentityClaimHash != dummyIdentityClaim {
			t.Fatalf("identity = %q, want the dev placeholder", sealed.Package.IdentityClaimHash)
		}
		if sealed.CertChain.VCEK != "" {
			t.Fatal("a dev receipt claims a VCEK certificate it does not have")
		}
		if sealed.Signature == "" || sealed.Pubkey == "" {
			t.Fatal("the receipt is not signed, so it proves nothing at all")
		}
		if sealed.Package.ReceiptID == "" {
			t.Fatal("the receipt has no id, so a caller cannot refer to it")
		}
		// The signature covers the placeholder mark: a caller cannot strip it.
		if !strings.Contains(string(mustJSON(t, sealed.Package)), "dev_placeholder") {
			t.Fatal("the placeholder mark is not part of the signed package")
		}
	})

	t.Run("without dev mode there is no receipt", func(t *testing.T) {
		t.Setenv("NEXQLOUD_DEV", "")
		// Without dev mode the receipt has to be accounted for like a real one, so the
		// model policy must be configured before attestation is even reached.
		t.Setenv("NEXQLOUD_MODEL_ID", "sealed-test-model")

		_, err := NewBuilder(priv, pub).Seal(Input{Prompt: "p", Response: "r"})
		if err == nil {
			t.Fatal("a machine with no attestation produced a receipt outside dev mode")
		}
		if !strings.Contains(err.Error(), "attestation") {
			t.Fatalf("error = %v, want it to name the missing attestation", err)
		}
	})
}

func TestSealWithHardwareAttestationDoesNotLookLikeADevReceipt(t *testing.T) {
	priv, pub := newKey(t)
	saved := requestReport
	defer func() { requestReport = saved }()
	requestReport = func(ed25519.PublicKey, []byte) (*sevsnp.Attestation, error) {
		return &sevsnp.Attestation{
			Report:           &sevsnp.Report{Measurement: []byte{0xaa, 0xbb}},
			CertificateChain: &sevsnp.CertificateChain{},
		}, nil
	}
	t.Setenv("NEXQLOUD_DEV", "1")

	sealed, err := NewBuilder(priv, pub).Seal(Input{Prompt: "p", Response: "r"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealed.Package.DevPlaceholder {
		t.Fatal("an attested receipt was marked as a development placeholder")
	}
	if sealed.Package.EnclaveMeasurement != "aabb" {
		t.Fatalf("measurement = %q, want the hardware report's", sealed.Package.EnclaveMeasurement)
	}
	if strings.Contains(string(mustJSON(t, sealed.Package)), "dev_placeholder") {
		t.Fatal("the placeholder mark appears on a real receipt, changing its signed bytes")
	}
}

func newKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return priv, pub
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}
