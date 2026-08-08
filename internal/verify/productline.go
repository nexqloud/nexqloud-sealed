//go:build js && wasm

package verify

import (
	"fmt"

	"github.com/google/go-sev-guest/proto/sevsnp"
)

func ProductLineFromReport(att *sevsnp.Attestation) (string, error) {
	if att == nil || att.Report == nil {
		return "", fmt.Errorf("missing attestation report")
	}
	if fms := att.Report.GetCpuid1EaxFms(); fms != 0 {
		line := ProductLineFromFms(fms)
		if line == "" || line == "Unknown" {
			return "", fmt.Errorf("unsupported AMD SEV product for FMS 0x%x", fms)
		}
		return line, nil
	}
	return "", fmt.Errorf("report does not include CPU product information")
}
