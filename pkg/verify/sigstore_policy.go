package verify

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed sigstore_trust/fulcio-intermediate.pem
var fulcioIntermediatePEM []byte

//go:embed sigstore_trust/fulcio-root.pem
var fulcioRootPEM []byte

//go:embed sigstore_trust/rekor-pubkey.pem
var rekorPubKeyPEM []byte

//go:embed sigstore_trust/rekor-logid.txt
var rekorLogIDHex string

const (
	DefaultOIDCIssuer = "https://token.actions.githubusercontent.com"
	DefaultRepo       = "nexqloud/nexqloud-sealed"
	// SAN URI prefix for the sealed-initrd workflow (ref suffix varies).
	DefaultWorkflowSANPrefix = "https://github.com/nexqloud/nexqloud-sealed/.github/workflows/sealed-initrd.yml@"
)

// MeasurementProof is a published CI gold measurement plus its cosign/Sigstore
// blob-signing bundle (Pattern 1). Payload must be the exact bytes that were
// signed (including trailing newline if present in expected-measurement.txt).
type MeasurementProof struct {
	Environment string          `json:"environment,omitempty"`
	GitSHA      string          `json:"git_sha,omitempty"`
	Payload     string          `json:"payload"`
	BundleJSON  json.RawMessage `json:"bundle"`
}

func (p MeasurementProof) PayloadBytes() []byte {
	return []byte(p.Payload)
}

// Allowlist is the append-only public index of published measurements.
type Allowlist struct {
	Schema      string           `json:"schema"`
	Environment string           `json:"environment"`
	Entries     []AllowlistEntry `json:"entries"`
}

type AllowlistEntry struct {
	GitSHA                       string `json:"git_sha"`
	Measurement                  string `json:"measurement"`
	ExpectedMeasurement          string `json:"expected_measurement"`
	ExpectedMeasurementSigstore  string `json:"expected_measurement_sigstore"`
	RekorLogIndex                int64  `json:"rekor_log_index,omitempty"`
}

func AllowlistURL(publicBase, env string) string {
	base := strings.TrimRight(publicBase, "/")
	if base == "" {
		base = DefaultR2PublicBase
	}
	return fmt.Sprintf("%s/%s/sealed-initrd/allowlist.json", base, strings.Trim(env, "/"))
}

func ParseAllowlist(data []byte) (Allowlist, error) {
	var a Allowlist
	if err := json.Unmarshal(data, &a); err != nil {
		return Allowlist{}, err
	}
	for i := range a.Entries {
		a.Entries[i].Measurement = strings.ToLower(strings.TrimSpace(a.Entries[i].Measurement))
	}
	return a, nil
}

func FindAllowlistEntry(a Allowlist, measurement string) (AllowlistEntry, bool) {
	m := strings.ToLower(strings.TrimSpace(measurement))
	for _, e := range a.Entries {
		if e.Measurement == m {
			return e, true
		}
	}
	return AllowlistEntry{}, false
}
