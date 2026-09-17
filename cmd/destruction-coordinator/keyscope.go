package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"nexqloud-sealed/internal/keyscope"
)

// operatorBaseURL derives an operator's URL from its id as <base>/v1/d/<id>, so a
// caller that knows the deployment can register a scope without the static map.
// Set from -operator-base in main.
var operatorBaseURL string

type createKeyScopeRequest struct {
	ScopeID string `json:"scope_id"`
	// Operators names the operator nodes to register. The platform knows them (it just
	// routed a request to that deployment), and an id-keyed static map goes stale the
	// moment a deployment is recreated and its endpoint key changes.
	Operators []string `json:"operators,omitempty"`
}

type keyScopeRegistration struct {
	OperatorID string `json:"operator_id"`
	SeedCommit string `json:"seed_commit"`
	Error      string `json:"error,omitempty"`
}

type createKeyScopeResponse struct {
	ScopeID    string                 `json:"scope_id"`
	SeedCommit string                 `json:"seed_commit"`
	Operators  []string               `json:"operators"`
	Detail     []keyScopeRegistration `json:"detail,omitempty"`
}

// handleCreateKeyScope registers a conversation key scope with every operator in
// the federation. It is the substrate-side entry point the platform calls, so the
// caller never needs to know operator addresses or handle scope seeds.
//
// One operator generates the seed; the coordinator hands the same seed to the rest
// and then drops it. Every operator must report the same seed commitment, otherwise
// the scope would have split key material and the later erasure proof would be
// meaningless.
func handleCreateKeyScope(operatorURLs map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req createKeyScopeRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		scopeID := strings.TrimSpace(req.ScopeID)
		if scopeID == "" {
			http.Error(w, "scope_id is required", http.StatusBadRequest)
			return
		}
		if !keyscope.IsScope(scopeID) {
			http.Error(w, "scope_id must be a "+keyscope.ScopePrefix+" scope", http.StatusBadRequest)
			return
		}

		// Operators named in the request win over the configured map.
		urls := operatorURLs
		if len(req.Operators) > 0 && operatorBaseURL != "" {
			urls = make(map[string]string, len(req.Operators))
			for _, id := range req.Operators {
				if id = strings.TrimSpace(id); id != "" {
					urls[id] = strings.TrimRight(operatorBaseURL, "/") + "/v1/d/" + id
				}
			}
		}

		ops := make([]string, 0, len(urls))
		for op := range urls {
			ops = append(ops, op)
		}
		sort.Strings(ops)
		if len(ops) == 0 {
			http.Error(w, "no operators configured", http.StatusServiceUnavailable)
			return
		}

		resp := createKeyScopeResponse{ScopeID: scopeID, Operators: []string{}, Detail: []keyScopeRegistration{}}
		var seed []byte

		for i, op := range ops {
			result, err := registerKeyScope(urls[op], scopeID, seed)
			if err != nil {
				resp.Detail = append(resp.Detail, keyScopeRegistration{OperatorID: op, Error: err.Error()})
				if len(seed) > 0 {
					zero(seed)
				}
				writeJSON(w, http.StatusBadGateway, resp)
				return
			}
			if i == 0 {
				seed = result.seed
				resp.SeedCommit = result.seedCommit
			} else if result.seedCommit != resp.SeedCommit {
				if len(seed) > 0 {
					zero(seed)
				}
				resp.Detail = append(resp.Detail, keyScopeRegistration{
					OperatorID: op,
					SeedCommit: result.seedCommit,
					Error:      fmt.Sprintf("seed_commit mismatch: registry holds %s", resp.SeedCommit),
				})
				writeJSON(w, http.StatusConflict, resp)
				return
			}
			resp.Operators = append(resp.Operators, op)
			resp.Detail = append(resp.Detail, keyScopeRegistration{OperatorID: op, SeedCommit: result.seedCommit})
		}

		if len(seed) > 0 {
			zero(seed)
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

type keyScopeRegisterResult struct {
	seed       []byte
	seedCommit string
}

// registerKeyScope calls one operator's /keyscope. When seed is nil the operator
// generates one and returns it; otherwise the caller's seed is sealed instead.
func registerKeyScope(operatorURL, scopeID string, seed []byte) (keyScopeRegisterResult, error) {
	payload := map[string]any{"scope_id": scopeID}
	if len(seed) > 0 {
		payload["seed_hex"] = hex.EncodeToString(seed)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return keyScopeRegisterResult{}, err
	}

	url := strings.TrimRight(operatorURL, "/") + "/keyscope"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return keyScopeRegisterResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return keyScopeRegisterResult{}, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return keyScopeRegisterResult{}, fmt.Errorf("operator %s: %s: %s", url, resp.Status, strings.TrimSpace(string(respBody)))
	}

	var out struct {
		SeedHex    string `json:"seed_hex"`
		SeedCommit string `json:"seed_commit"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return keyScopeRegisterResult{}, fmt.Errorf("decode operator response: %w", err)
	}
	if out.SeedCommit == "" {
		return keyScopeRegisterResult{}, fmt.Errorf("operator %s returned no seed_commit", url)
	}

	result := keyScopeRegisterResult{seedCommit: out.SeedCommit}
	if out.SeedHex != "" {
		generated, err := hex.DecodeString(out.SeedHex)
		if err != nil {
			return keyScopeRegisterResult{}, fmt.Errorf("operator %s returned a non-hex seed: %w", url, err)
		}
		result.seed = generated
	}
	return result, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
