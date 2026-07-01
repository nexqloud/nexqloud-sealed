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
	if digest != "sha256:a679662e01eb3bb49252a0470f7320dca9a53c1f44599cd74b190ad10732e65c" {
		t.Fatalf("digest = %s", digest)
	}
}
