//go:build js && wasm

package main

import (
	"encoding/json"
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

func verifyReceipt(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errorResult("expected receipt JSON string")
	}

	receiptJSON := args[0].String()
	challengeHex := ""
	if len(args) > 1 {
		challengeHex = args[1].String()
	}
	var measurements []string
	if len(args) > 2 && args[2].Truthy() {
		raw := args[2].String()
		if raw != "" {
			if err := json.Unmarshal([]byte(raw), &measurements); err != nil {
				return errorResult("parse measurements JSON: " + err.Error())
			}
		}
	}

	result := verify.VerifyReceiptJSONOpts([]byte(receiptJSON), verify.VerifyOpts{
		ChallengeHex: challengeHex,
		RootsCatalog: hardwareRootsCatalog,
		Measurements: measurements,
	})
	out, err := json.Marshal(result)
	if err != nil {
		return errorResult(err.Error())
	}
	return string(out)
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
