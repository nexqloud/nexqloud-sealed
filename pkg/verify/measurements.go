package verify

import (
	"encoding/json"
	"fmt"
	"strings"
)

const DefaultR2PublicBase = "https://pub-84b99924d959400aa97608c84bbd8000.r2.dev"

// InitrdRelease is the public release.json published by sealed-initrd CI to R2.
type InitrdRelease struct {
	Schema      string `json:"schema"`
	Environment string `json:"environment"`
	GitSHA      string `json:"git_sha"`
	Measurement string `json:"measurement"`
	Objects     struct {
		ExpectedMeasurement         string `json:"expected_measurement"`
		ExpectedMeasurementSigstore string `json:"expected_measurement_sigstore"`
	} `json:"objects"`
}

// InitrdReleaseURL returns the latest release.json URL for a deploy environment
// (staging|production).
func InitrdReleaseURL(publicBase, env string) string {
	base := strings.TrimRight(publicBase, "/")
	if base == "" {
		base = DefaultR2PublicBase
	}
	env = strings.Trim(env, "/")
	return fmt.Sprintf("%s/%s/sealed-initrd/latest/release.json", base, env)
}

func ParseInitrdRelease(data []byte) (InitrdRelease, error) {
	var rel InitrdRelease
	if err := json.Unmarshal(data, &rel); err != nil {
		return InitrdRelease{}, err
	}
	rel.Measurement = strings.TrimSpace(strings.ToLower(rel.Measurement))
	if rel.Measurement == "" {
		return InitrdRelease{}, fmt.Errorf("release.json missing measurement")
	}
	if len(rel.Measurement) != 96 {
		return InitrdRelease{}, fmt.Errorf("measurement must be 96 hex chars, got %d", len(rel.Measurement))
	}
	for _, c := range rel.Measurement {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return InitrdRelease{}, fmt.Errorf("measurement is not hex")
		}
	}
	return rel, nil
}

// MergeMeasurements returns unique hex measurements, extras first, then fallback.
func MergeMeasurements(extras, fallback []string) []string {
	seen := make(map[string]struct{}, len(extras)+len(fallback))
	out := make([]string, 0, len(extras)+len(fallback))
	add := func(list []string) {
		for _, m := range list {
			m = strings.TrimSpace(strings.ToLower(m))
			if m == "" {
				continue
			}
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			out = append(out, m)
		}
	}
	add(extras)
	add(fallback)
	return out
}

// EffectiveMeasurements returns the published allowlist measurements only.
// There is no embedded/hardcoded measurement catalog.
func EffectiveMeasurements(published []string) []string {
	return MergeMeasurements(published, nil)
}
