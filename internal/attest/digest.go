package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/encoding/protojson"
)

func ReportDigest(attJSON []byte) (string, error) {
	if len(attJSON) == 0 {
		return "", fmt.Errorf("missing attestation")
	}

	att := &sevsnp.Attestation{}
	if err := protojson.Unmarshal(attJSON, att); err != nil {
		return "", fmt.Errorf("parse attestation: %w", err)
	}
	if att.Report == nil {
		return "", fmt.Errorf("missing attestation report")
	}

	raw, err := abi.ReportToAbiBytes(att.Report)
	if err != nil {
		return "", fmt.Errorf("report abi: %w", err)
	}

	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
