//go:build !(js && wasm)

package verify

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// FetchInitrdRelease loads latest release.json for env from the public R2 base.
func FetchInitrdRelease(publicBase, env string) (InitrdRelease, error) {
	url := InitrdReleaseURL(publicBase, env)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return InitrdRelease{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return InitrdRelease{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return InitrdRelease{}, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return ParseInitrdRelease(body)
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
