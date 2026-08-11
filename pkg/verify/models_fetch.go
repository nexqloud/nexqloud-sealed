//go:build !(js && wasm)

package verify

import (
	"fmt"
	"strings"
)

// FetchModelsAllowlist loads sealed-models/allowlist.json for env from publicBase.
func FetchModelsAllowlist(publicBase, env string) (ModelsAllowlist, error) {
	body, err := httpGetLimited(ModelsAllowlistURL(publicBase, env), 4<<20)
	if err != nil {
		return ModelsAllowlist{}, err
	}
	return ParseModelsAllowlist(body)
}

// FetchModelsAllowlistFromURL loads an allowlist from an absolute URL
// (R2 object, CF /api/models-allowlist, or static Pages path).
func FetchModelsAllowlistFromURL(url string) (ModelsAllowlist, error) {
	body, err := httpGetLimited(url, 4<<20)
	if err != nil {
		return ModelsAllowlist{}, err
	}
	return ParseModelsAllowlist(body)
}

// FetchAllowlistModelCommitments returns unique model commitments from envs.
func FetchAllowlistModelCommitments(publicBase string, envs []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	var lastErr error
	for _, env := range envs {
		env = strings.TrimSpace(env)
		if env == "" {
			continue
		}
		a, err := FetchModelsAllowlist(publicBase, env)
		if err != nil {
			lastErr = err
			continue
		}
		for _, e := range a.Entries {
			c := strings.TrimSpace(e.Commitment)
			if c == "" {
				continue
			}
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

// FetchModelAttestIssuersAllowlist loads sealed-model-attest-issuers/allowlist.json.
func FetchModelAttestIssuersAllowlist(publicBase, env string) (ModelAttestIssuersAllowlist, error) {
	body, err := httpGetLimited(ModelAttestIssuersAllowlistURL(publicBase, env), 1<<20)
	if err != nil {
		return ModelAttestIssuersAllowlist{}, err
	}
	return ParseModelAttestIssuersAllowlist(body)
}

// FetchAllowlistModelAttestIssuers returns unique issuer pubkeys from envs.
func FetchAllowlistModelAttestIssuers(publicBase string, envs []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	var lastErr error
	for _, env := range envs {
		env = strings.TrimSpace(env)
		if env == "" {
			continue
		}
		a, err := FetchModelAttestIssuersAllowlist(publicBase, env)
		if err != nil {
			lastErr = err
			continue
		}
		for _, e := range a.Entries {
			c := strings.ToLower(strings.TrimSpace(e.Pubkey))
			if c == "" || strings.HasPrefix(c, "replace_") {
				continue
			}
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

// ResolveModelCommitment looks up modelID across envs on publicBase.
func ResolveModelCommitment(publicBase string, envs []string, modelID string) (string, error) {
	id := strings.TrimSpace(modelID)
	if id == "" {
		return "", fmt.Errorf("model id is empty")
	}
	var lastErr error
	for _, env := range envs {
		env = strings.TrimSpace(env)
		if env == "" {
			continue
		}
		a, err := FetchModelsAllowlist(publicBase, env)
		if err != nil {
			lastErr = err
			continue
		}
		if c, ok := FindModelCommitment(a, id); ok {
			return c, nil
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("model %q not in allowlist: %w", id, lastErr)
	}
	return "", fmt.Errorf("model %q not in sealed-models allowlist", id)
}
