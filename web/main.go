//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"syscall/js"

	"nexqloud-sealed/pkg/verify"
)

var hardwareRootsCatalog map[string]verify.HardwareRoots

func init() {
	catalog, err := loadHardwareRootsCatalog()
	if err != nil {
		panic("load AMD root certificates: " + err.Error())
	}
	hardwareRootsCatalog = catalog
}

func main() {
	js.Global().Set("verifyReceipt", js.FuncOf(verifyReceipt))
	js.Global().Set("verifyDeletion", js.FuncOf(verifyDeletion))
	<-make(chan struct{})
}

// verifyReceipt(receiptJSON, challengeHex?, optsJSON?)
// optsJSON may be:
//   - legacy: JSON array of measurement hex strings
//   - object: {"measurements":[...],"proofs":[{"payload":"...","bundle":{...},...}]}
func verifyReceipt(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errorResult("expected receipt JSON string")
	}

	receiptJSON := args[0].String()
	challengeHex := ""
	if len(args) > 1 {
		challengeHex = args[1].String()
	}

	opts := verify.VerifyOpts{
		ChallengeHex: challengeHex,
		RootsCatalog: hardwareRootsCatalog,
	}
	if len(args) > 2 && args[2].Truthy() {
		raw := args[2].String()
		if raw != "" {
			if err := applyVerifyOptsJSON(&opts, raw); err != nil {
				return errorResult(err.Error())
			}
		}
	}

	result := verify.VerifyReceiptJSONOpts([]byte(receiptJSON), opts)
	out, err := json.Marshal(result)
	if err != nil {
		return errorResult(err.Error())
	}
	return string(out)
}

func applyVerifyOptsJSON(opts *verify.VerifyOpts, raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	if trimmed[0] == '[' {
		var measurements []string
		if err := json.Unmarshal([]byte(raw), &measurements); err != nil {
			return fmt.Errorf("parse measurements JSON: %w", err)
		}
		opts.Measurements = measurements
		return nil
	}

	var wire struct {
		Measurements []string                  `json:"measurements"`
		Proofs       []verify.MeasurementProof `json:"proofs"`
	}
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		return fmt.Errorf("parse verify opts JSON: %w", err)
	}
	opts.Measurements = wire.Measurements
	opts.MeasurementProofs = wire.Proofs
	return nil
}

func errorResult(msg string) string {
	out, _ := json.Marshal(verify.ReceiptResult{Error: msg})
	return string(out)
}

func verifyDeletion(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return deletionErrorResult("expected proof JSON and receipts JSON array")
	}

	proofJSON := []byte(args[0].String())
	receiptsJSON := []byte(args[1].String())
	registryRecordJSON := []byte{}
	if len(args) > 2 {
		registryRecordJSON = []byte(args[2].String())
	}
	challengeHex := ""
	if len(args) > 3 {
		challengeHex = args[3].String()
	}

	result, err := verify.VerifyDeletionJSON(proofJSON, receiptsJSON, registryRecordJSON, challengeHex, hardwareRootsCatalog)
	if err != nil {
		return deletionErrorResult(err.Error())
	}
	out, err := json.Marshal(result)
	if err != nil {
		return deletionErrorResult(err.Error())
	}
	return string(out)
}

func deletionErrorResult(msg string) string {
	out, _ := json.Marshal(verify.DeletionResult{Error: msg, OverallOK: false})
	return string(out)
}
