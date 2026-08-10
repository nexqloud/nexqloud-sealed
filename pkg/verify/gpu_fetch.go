//go:build !(js && wasm)

package verify

import (
	"strings"
)

func FetchGPUPoliciesAllowlist(publicBase, env string) (GPUPoliciesAllowlist, error) {
	body, err := httpGetLimited(GPUPoliciesAllowlistURL(publicBase, env), 1<<20)
	if err != nil {
		return GPUPoliciesAllowlist{}, err
	}
	return ParseGPUPoliciesAllowlist(body)
}

func FetchWipeIssuersAllowlist(publicBase, env string) (WipeIssuersAllowlist, error) {
	body, err := httpGetLimited(WipeIssuersAllowlistURL(publicBase, env), 1<<20)
	if err != nil {
		return WipeIssuersAllowlist{}, err
	}
	return ParseWipeIssuersAllowlist(body)
}

func FetchWipeWorkersAllowlist(publicBase, env string) (WipeWorkersAllowlist, error) {
	body, err := httpGetLimited(WipeWorkersAllowlistURL(publicBase, env), 1<<20)
	if err != nil {
		return WipeWorkersAllowlist{}, err
	}
	return ParseWipeWorkersAllowlist(body)
}

func FetchAllowlistGPUPolicyHashes(publicBase string, envs []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	var lastErr error
	for _, env := range envs {
		env = strings.TrimSpace(env)
		if env == "" {
			continue
		}
		a, err := FetchGPUPoliciesAllowlist(publicBase, env)
		if err != nil {
			lastErr = err
			continue
		}
		for _, e := range a.Entries {
			c := strings.TrimSpace(e.PolicyHash)
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

func FetchAllowlistWipeIssuers(publicBase string, envs []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	var lastErr error
	for _, env := range envs {
		env = strings.TrimSpace(env)
		if env == "" {
			continue
		}
		a, err := FetchWipeIssuersAllowlist(publicBase, env)
		if err != nil {
			lastErr = err
			continue
		}
		for _, e := range a.Entries {
			c := strings.ToLower(strings.TrimSpace(e.Pubkey))
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

func FetchAllowlistWipeWorkers(publicBase string, envs []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	var lastErr error
	for _, env := range envs {
		env = strings.TrimSpace(env)
		if env == "" {
			continue
		}
		a, err := FetchWipeWorkersAllowlist(publicBase, env)
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
