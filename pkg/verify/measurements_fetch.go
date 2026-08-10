//go:build !(js && wasm)

package verify

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func httpGetLimited(url string, limit int64) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return body, nil
}

// FetchInitrdRelease loads latest release.json for env from the public R2 base.
func FetchInitrdRelease(publicBase, env string) (InitrdRelease, error) {
	body, err := httpGetLimited(InitrdReleaseURL(publicBase, env), 1<<20)
	if err != nil {
		return InitrdRelease{}, err
	}
	return ParseInitrdRelease(body)
}

// FetchAllowlist loads the append-only allowlist for env.
func FetchAllowlist(publicBase, env string) (Allowlist, error) {
	body, err := httpGetLimited(AllowlistURL(publicBase, env), 4<<20)
	if err != nil {
		return Allowlist{}, err
	}
	return ParseAllowlist(body)
}

// ObjectURL joins publicBase with a relative object key from release/allowlist.
func ObjectURL(publicBase, key string) string {
	base := strings.TrimRight(publicBase, "/")
	if base == "" {
		base = DefaultR2PublicBase
	}
	key = strings.TrimLeft(key, "/")
	if strings.HasPrefix(key, "http://") || strings.HasPrefix(key, "https://") {
		return key
	}
	return base + "/" + key
}

// FetchMeasurementProof loads the signed measurement payload + cosign bundle
// for an allowlist entry.
func FetchMeasurementProof(publicBase string, env string, entry AllowlistEntry) (MeasurementProof, error) {
	payloadKey := entry.ExpectedMeasurement
	bundleKey := entry.ExpectedMeasurementSigstore
	if payloadKey == "" || bundleKey == "" {
		return MeasurementProof{}, fmt.Errorf("allowlist entry missing object keys")
	}
	payload, err := httpGetLimited(ObjectURL(publicBase, payloadKey), 1<<20)
	if err != nil {
		return MeasurementProof{}, err
	}
	bundle, err := httpGetLimited(ObjectURL(publicBase, bundleKey), 4<<20)
	if err != nil {
		return MeasurementProof{}, err
	}
	return MeasurementProof{
		Environment: env,
		GitSHA:      entry.GitSHA,
		Payload:     string(payload),
		BundleJSON:  bundle,
	}, nil
}

// FetchProofForMeasurement finds measurement in allowlists for envs and loads
// its Sigstore proof. Falls back to latest/release.json when allowlist is
// missing or does not yet list the measurement.
func FetchProofForMeasurement(publicBase string, envs []string, measurement string) (MeasurementProof, error) {
	m := strings.ToLower(strings.TrimSpace(measurement))
	var lastErr error
	for _, env := range envs {
		a, err := FetchAllowlist(publicBase, env)
		if err != nil {
			lastErr = err
		} else if entry, ok := FindAllowlistEntry(a, m); ok {
			proof, err := FetchMeasurementProof(publicBase, env, entry)
			if err != nil {
				lastErr = err
				continue
			}
			return proof, nil
		}
	}
	for _, env := range envs {
		rel, err := FetchInitrdRelease(publicBase, env)
		if err != nil {
			lastErr = err
			continue
		}
		if rel.Measurement != m {
			continue
		}
		entry := AllowlistEntry{
			GitSHA:                      rel.GitSHA,
			Measurement:                 rel.Measurement,
			ExpectedMeasurement:         rel.Objects.ExpectedMeasurement,
			ExpectedMeasurementSigstore: rel.Objects.ExpectedMeasurementSigstore,
		}
		if entry.ExpectedMeasurement == "" {
			entry.ExpectedMeasurement = fmt.Sprintf("%s/sealed-initrd/%s/expected-measurement.txt", env, rel.GitSHA)
		}
		if entry.ExpectedMeasurementSigstore == "" {
			entry.ExpectedMeasurementSigstore = fmt.Sprintf("%s/sealed-initrd/%s/expected-measurement.sigstore.json", env, rel.GitSHA)
		}
		proof, err := FetchMeasurementProof(publicBase, env, entry)
		if err != nil {
			lastErr = err
			continue
		}
		return proof, nil
	}
	if lastErr != nil {
		return MeasurementProof{}, lastErr
	}
	return MeasurementProof{}, fmt.Errorf("measurement not in allowlist")
}

// FetchPublishedMeasurements loads latest measurements for the given envs.
// Missing envs are skipped; returns an error only if every fetch fails and
// envs was non-empty.
func FetchPublishedMeasurements(publicBase string, envs []string) ([]string, error) {
	var (
		out     []string
		lastErr error
		anyOK   bool
	)
	for _, env := range envs {
		rel, err := FetchInitrdRelease(publicBase, env)
		if err != nil {
			lastErr = err
			continue
		}
		anyOK = true
		out = append(out, rel.Measurement)
	}
	if !anyOK && len(envs) > 0 {
		return nil, lastErr
	}
	return MergeMeasurements(out, nil), nil
}

// FetchAllowlistMeasurements returns every measurement listed in allowlists.
func FetchAllowlistMeasurements(publicBase string, envs []string) ([]string, error) {
	var (
		out     []string
		lastErr error
		anyOK   bool
	)
	for _, env := range envs {
		a, err := FetchAllowlist(publicBase, env)
		if err != nil {
			lastErr = err
			continue
		}
		anyOK = true
		for _, e := range a.Entries {
			out = append(out, e.Measurement)
		}
	}
	if !anyOK && len(envs) > 0 {
		return nil, lastErr
	}
	return MergeMeasurements(out, nil), nil
}
