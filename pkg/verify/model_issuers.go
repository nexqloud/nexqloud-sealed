package verify

import (
	"encoding/json"
	"fmt"
	"strings"
)

const ModelAttestIssuersAllowlistSchema = "nexqloud-sealed-model-attest-issuers-allowlist/1"

type ModelAttestIssuersAllowlist struct {
	Schema      string                            `json:"schema"`
	Environment string                            `json:"environment"`
	Entries     []ModelAttestIssuersAllowlistEntry `json:"entries"`
}

type ModelAttestIssuersAllowlistEntry struct {
	ID     string `json:"id"`
	Pubkey string `json:"pubkey"`
	Issuer string `json:"issuer,omitempty"`
	Note   string `json:"note,omitempty"`
}

func ModelAttestIssuersAllowlistURL(publicBase, env string) string {
	base := strings.TrimRight(publicBase, "/")
	if base == "" {
		base = DefaultR2PublicBase
	}
	return fmt.Sprintf("%s/%s/sealed-model-attest-issuers/allowlist.json", base, strings.Trim(env, "/"))
}

func ParseModelAttestIssuersAllowlist(data []byte) (ModelAttestIssuersAllowlist, error) {
	var a ModelAttestIssuersAllowlist
	if err := json.Unmarshal(data, &a); err != nil {
		return ModelAttestIssuersAllowlist{}, err
	}
	for i := range a.Entries {
		a.Entries[i].ID = strings.TrimSpace(a.Entries[i].ID)
		a.Entries[i].Pubkey = strings.ToLower(strings.TrimSpace(a.Entries[i].Pubkey))
		a.Entries[i].Issuer = strings.TrimSpace(a.Entries[i].Issuer)
	}
	return a, nil
}

func EffectiveModelAttestIssuers(published []string) []string {
	var cleaned []string
	for _, p := range published {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || strings.HasPrefix(p, "replace_") {
			continue
		}
		cleaned = append(cleaned, p)
	}
	return mergeUnique(cleaned, nil)
}
