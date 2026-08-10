package verify

import (
	"encoding/json"
	"fmt"
	"strings"

	"nexqloud-sealed/internal/gpu"
)

const (
	GPUPoliciesAllowlistSchema = "nexqloud-sealed-gpu-policies-allowlist/1"
	WipeIssuersAllowlistSchema = "nexqloud-sealed-wipe-issuers-allowlist/1"
	WipeWorkersAllowlistSchema = "nexqloud-sealed-wipe-workers-allowlist/1"
)

// EmbeddedGPUPolicyHashes includes the mock-model policy for unit tests.
var EmbeddedGPUPolicyHashes = func() []string {
	h, err := gpu.Hash(gpu.DevReferencePolicy())
	if err != nil {
		panic(err)
	}
	return []string{h}
}()

type GPUPoliciesAllowlist struct {
	Schema      string                      `json:"schema"`
	Environment string                      `json:"environment"`
	Entries     []GPUPoliciesAllowlistEntry `json:"entries"`
}

type GPUPoliciesAllowlistEntry struct {
	ID         string `json:"id"`
	PolicyHash string `json:"policy_hash"`
	Model      string `json:"model,omitempty"`
}

type WipeIssuersAllowlist struct {
	Schema      string                      `json:"schema"`
	Environment string                      `json:"environment"`
	Entries     []WipeIssuersAllowlistEntry `json:"entries"`
}

type WipeIssuersAllowlistEntry struct {
	ID     string `json:"id"`
	Pubkey string `json:"pubkey"`
	Issuer string `json:"issuer,omitempty"`
}

type WipeWorkersAllowlist struct {
	Schema      string                      `json:"schema"`
	Environment string                      `json:"environment"`
	Entries     []WipeWorkersAllowlistEntry `json:"entries"`
}

type WipeWorkersAllowlistEntry struct {
	ID         string `json:"id"`
	Commitment string `json:"commitment"`
}

func GPUPoliciesAllowlistURL(publicBase, env string) string {
	base := strings.TrimRight(publicBase, "/")
	if base == "" {
		base = DefaultR2PublicBase
	}
	return fmt.Sprintf("%s/%s/sealed-gpu-policies/allowlist.json", base, strings.Trim(env, "/"))
}

func WipeIssuersAllowlistURL(publicBase, env string) string {
	base := strings.TrimRight(publicBase, "/")
	if base == "" {
		base = DefaultR2PublicBase
	}
	return fmt.Sprintf("%s/%s/sealed-wipe-issuers/allowlist.json", base, strings.Trim(env, "/"))
}

func WipeWorkersAllowlistURL(publicBase, env string) string {
	base := strings.TrimRight(publicBase, "/")
	if base == "" {
		base = DefaultR2PublicBase
	}
	return fmt.Sprintf("%s/%s/sealed-wipe-workers/allowlist.json", base, strings.Trim(env, "/"))
}

func ParseGPUPoliciesAllowlist(data []byte) (GPUPoliciesAllowlist, error) {
	var a GPUPoliciesAllowlist
	if err := json.Unmarshal(data, &a); err != nil {
		return GPUPoliciesAllowlist{}, err
	}
	for i := range a.Entries {
		a.Entries[i].ID = strings.TrimSpace(a.Entries[i].ID)
		a.Entries[i].PolicyHash = strings.TrimSpace(a.Entries[i].PolicyHash)
	}
	return a, nil
}

func ParseWipeIssuersAllowlist(data []byte) (WipeIssuersAllowlist, error) {
	var a WipeIssuersAllowlist
	if err := json.Unmarshal(data, &a); err != nil {
		return WipeIssuersAllowlist{}, err
	}
	for i := range a.Entries {
		a.Entries[i].ID = strings.TrimSpace(a.Entries[i].ID)
		a.Entries[i].Pubkey = strings.ToLower(strings.TrimSpace(a.Entries[i].Pubkey))
	}
	return a, nil
}

func ParseWipeWorkersAllowlist(data []byte) (WipeWorkersAllowlist, error) {
	var a WipeWorkersAllowlist
	if err := json.Unmarshal(data, &a); err != nil {
		return WipeWorkersAllowlist{}, err
	}
	for i := range a.Entries {
		a.Entries[i].ID = strings.TrimSpace(a.Entries[i].ID)
		a.Entries[i].Commitment = strings.TrimSpace(a.Entries[i].Commitment)
	}
	return a, nil
}

func EffectiveGPUPolicyHashes(published []string) []string {
	return mergeUnique(published, EmbeddedGPUPolicyHashes)
}

func EffectiveWipeIssuers(published []string) []string {
	return mergeUnique(published, nil)
}

func EffectiveWipeWorkers(published []string) []string {
	return mergeUnique(published, nil)
}

func mergeUnique(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	add := func(c string) {
		c = strings.TrimSpace(c)
		if c == "" {
			return
		}
		if _, ok := seen[c]; ok {
			return
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	for _, c := range a {
		add(c)
	}
	for _, c := range b {
		add(c)
	}
	return out
}
