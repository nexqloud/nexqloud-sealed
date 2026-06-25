//go:build js && wasm

package verify

import (
	"fmt"

	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
)

func ProductLineFromReport(att *sevsnp.Attestation) (string, error) {
	if att == nil || att.Report == nil {
		return "", fmt.Errorf("missing attestation report")
	}
	if fms := att.Report.GetCpuid1EaxFms(); fms != 0 {
		return kds.ProductLineFromFms(fms), nil
	}
	return "", fmt.Errorf("report does not include CPU product information")
}
