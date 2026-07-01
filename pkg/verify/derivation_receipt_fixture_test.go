package verify

import (
	"os"
	"testing"
)

func TestVerifyDerivationReceiptFixture(t *testing.T) {
	t.Skip("regenerate derivation_receipt.json on the TEE VM after pulling attest.ReportDigest change")
	b, err := os.ReadFile("derivation_receipt.json")
	if err != nil {
		t.Fatal(err)
	}

	result := VerifyReceiptJSON(b, "", nil)
	if result.Error != "" {
		t.Fatalf("error: %s", result.Error)
	}

	for _, check := range result.Checks {
		if !check.OK {
			t.Fatalf("%s failed: %s", check.ID, check.Detail)
		}
	}
	if !result.OverallOK {
		t.Fatal("overall_ok is false")
	}
}
