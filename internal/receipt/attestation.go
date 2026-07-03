package receipt

import (
	"encoding/json"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/encoding/protojson"
)

func MarshalAttestation(att *sevsnp.Attestation) (json.RawMessage, error) {
	if att == nil || att.Report == nil {
		return json.RawMessage("{}"), nil
	}
	raw, err := protojson.Marshal(&sevsnp.Attestation{Report: att.Report})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

func NormalizeAttestationJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return json.RawMessage("{}"), nil
	}
	att := &sevsnp.Attestation{}
	if err := protojson.Unmarshal(raw, att); err != nil {
		return nil, err
	}
	return MarshalAttestation(att)
}
