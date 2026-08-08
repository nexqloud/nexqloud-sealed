package verify

import (
	"testing"

	"github.com/google/go-sev-guest/abi"
)

func TestProductLineFromFmsSienaMapsToGenoa(t *testing.T) {
	// EPYC 8124P: family 0x19, model 0xa0, stepping 2
	fms := abi.FmsToCpuid1Eax(0x19, 0xa0, 2)
	if got := ProductLineFromFms(fms); got != "Genoa" {
		t.Fatalf("Siena FMS product line = %q, want Genoa", got)
	}
}

func TestProductLineFromFmsKnownLines(t *testing.T) {
	cases := []struct {
		family, model, stepping byte
		want                    string
	}{
		{0x19, 0x01, 1, "Milan"},
		{0x19, 0x11, 1, "Genoa"},
		{0x1a, 0x02, 0, "Turin"},
	}
	for _, tc := range cases {
		fms := abi.FmsToCpuid1Eax(tc.family, tc.model, tc.stepping)
		if got := ProductLineFromFms(fms); got != tc.want {
			t.Fatalf("family=0x%x model=0x%x -> %q, want %q", tc.family, tc.model, got, tc.want)
		}
	}
}
