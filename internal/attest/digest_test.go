package attest

import (
	"encoding/json"
	"os"
	"testing"
)

func TestReportDigestFixture(t *testing.T) {
	b, err := os.ReadFile("../../pkg/verify/derivation_receipt.json")
	if err != nil {
		t.Skip(err)
	}

	var wrapper struct {
		Attestation json.RawMessage `json:"attestation"`
	}
	if err := json.Unmarshal(b, &wrapper); err != nil {
		t.Fatal(err)
	}

	digest, err := ReportDigest(wrapper.Attestation)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256:37eff46598e5a80eca2936133615b9b8dad718f290f4352e30aaed2d0feb1511" {
		t.Fatalf("digest = %s", digest)
	}
}
