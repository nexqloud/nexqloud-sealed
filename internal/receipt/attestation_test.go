package receipt

import (
	"encoding/json"
	"testing"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestMarshalAttestationReportOnly(t *testing.T) {
	att := &sevsnp.Attestation{
		Report: &sevsnp.Report{Version: 5},
		CertificateChain: &sevsnp.CertificateChain{
			VcekCert: []byte("vcek"),
		},
	}
	raw, err := MarshalAttestation(att)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 1 {
		t.Fatalf("expected only report in marshaled attestation, got keys %v", doc)
	}
	if _, ok := doc["report"]; !ok {
		t.Fatal("expected report in marshaled attestation")
	}
}

func TestNormalizeAttestationJSONReportOnly(t *testing.T) {
	att := &sevsnp.Attestation{
		Report: &sevsnp.Report{Version: 5},
		CertificateChain: &sevsnp.CertificateChain{
			VcekCert: []byte("vcek"),
		},
	}
	full, err := protojson.Marshal(att)
	if err != nil {
		t.Fatal(err)
	}

	normalized, err := NormalizeAttestationJSON(full)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(normalized, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 1 {
		t.Fatalf("expected only report after normalization, got keys %v", doc)
	}
	if _, ok := doc["report"]; !ok {
		t.Fatal("expected report after normalization")
	}
}
