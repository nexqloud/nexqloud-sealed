package verify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ModelsAllowlist is the public Model Legit index (R2 / Pages).
type ModelsAllowlist struct {
	Schema      string                 `json:"schema"`
	Environment string                 `json:"environment"`
	Entries     []ModelsAllowlistEntry `json:"entries"`
}

type ModelsAllowlistEntry struct {
	ID                      string `json:"id"`
	Commitment              string `json:"commitment"`
	HFRepo                  string `json:"hf_repo,omitempty"`
	Revision                string `json:"revision,omitempty"`
	File                    string `json:"file,omitempty"`
	Quant                   string `json:"quant,omitempty"`
	ExpectedModelCommitment string `json:"expected_model_commitment,omitempty"`
	ModelMeta               string `json:"model_meta,omitempty"`
}

func ModelsAllowlistURL(publicBase, env string) string {
	base := strings.TrimRight(publicBase, "/")
	if base == "" {
		base = DefaultR2PublicBase
	}
	return fmt.Sprintf("%s/%s/sealed-models/allowlist.json", base, strings.Trim(env, "/"))
}

func ParseModelsAllowlist(data []byte) (ModelsAllowlist, error) {
	var a ModelsAllowlist
	if err := json.Unmarshal(data, &a); err != nil {
		return ModelsAllowlist{}, err
	}
	for i := range a.Entries {
		a.Entries[i].ID = strings.TrimSpace(a.Entries[i].ID)
		a.Entries[i].Commitment = strings.TrimSpace(a.Entries[i].Commitment)
	}
	return a, nil
}

func FindModelCommitment(a ModelsAllowlist, modelID string) (string, bool) {
	id := strings.TrimSpace(modelID)
	for _, e := range a.Entries {
		if e.ID == id && e.Commitment != "" {
			return e.Commitment, true
		}
	}
	return "", false
}

// EffectiveModelCommitments returns published model commitments only.
// There is no embedded production catalog; tests pass commitments explicitly.
func EffectiveModelCommitments(published []string) []string {
	return MergeMeasurements(published, nil)
}
