package attest

import (
	_ "embed"
	"encoding/json"
)

//go:embed testdata/attestation.json
var testAttestationJSON []byte

func TestAttestationJSON() json.RawMessage {
	return testAttestationJSON
}
