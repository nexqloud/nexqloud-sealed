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

	result := verify.VerifyReceiptJSON([]byte(receiptJSON), challengeHex, hardwareRootsCatalog)
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
