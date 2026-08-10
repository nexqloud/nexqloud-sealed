package verify

import (
	"os"
	"strings"
	"testing"
)

func TestVerifyCosignBlobBundleFixture(t *testing.T) {
	payload, err := os.ReadFile("testdata/expected-measurement.txt")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile("testdata/expected-measurement.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCosignBlobBundle(payload, bundle); err != nil {
		t.Fatalf("VerifyCosignBlobBundle: %v", err)
	}
	got := MeasurementFromPayload(payload)
	if len(got) != 96 {
		t.Fatalf("measurement len=%d", len(got))
	}
}

func TestVerifyCosignBlobBundleRejectsTamper(t *testing.T) {
	payload, err := os.ReadFile("testdata/expected-measurement.txt")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile("testdata/expected-measurement.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, payload...)
	tampered[0] ^= 0x01
	if err := VerifyCosignBlobBundle(tampered, bundle); err == nil {
		t.Fatal("expected failure for tampered payload")
	}
}

func TestAllowlistURL(t *testing.T) {
	u := AllowlistURL(DefaultR2PublicBase, "staging")
	want := DefaultR2PublicBase + "/staging/sealed-initrd/allowlist.json"
	if u != want {
		t.Fatalf("got %s want %s", u, want)
	}
}

func TestFindAllowlistEntry(t *testing.T) {
	a, err := ParseAllowlist([]byte(`{"schema":"x","environment":"staging","entries":[{"measurement":"AA","git_sha":"1"},{"measurement":"bb","git_sha":"2"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	e, ok := FindAllowlistEntry(a, "aa")
	if !ok || e.GitSHA != "1" {
		t.Fatalf("got %#v ok=%v", e, ok)
	}
}

func TestCheckCodeLegitWithSigstoreProof(t *testing.T) {
	payload, err := os.ReadFile("testdata/expected-measurement.txt")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile("testdata/expected-measurement.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	meas := MeasurementFromPayload(payload)
	check := checkCodeLegit(
		map[string]any{"enclave_measurement": meas},
		nil,
		VerifyOpts{
			MeasurementProofs: []MeasurementProof{{
				GitSHA:     "deadbeef",
				Payload:    string(payload),
				BundleJSON: bundle,
			}},
		},
	)
	if !check.OK {
		t.Fatalf("expected OK, got %+v", check)
	}
}

func TestCheckCodeLegitProofMismatch(t *testing.T) {
	payload, err := os.ReadFile("testdata/expected-measurement.txt")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile("testdata/expected-measurement.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	check := checkCodeLegit(
		map[string]any{"enclave_measurement": strings.Repeat("ab", 48)},
		nil,
		VerifyOpts{
			MeasurementProofs: []MeasurementProof{{
				Payload:    string(payload),
				BundleJSON: bundle,
			}},
		},
	)
	if check.OK {
		t.Fatalf("expected fail, got %+v", check)
	}
}
