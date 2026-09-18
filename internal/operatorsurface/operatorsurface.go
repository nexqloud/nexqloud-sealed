// Package operatorsurface is the per-operator node surface of federated
// cryptographic erasure: the endpoints a node must serve to join a destruction
// quorum.
//
// It is shared by cmd/operator (the standalone demo/operator binary) and cmd/shim
// (a sealed deployment), because in the deployment model a sealed deployment IS an
// operator node: it holds a sealed copy of each scope seed, so it is the thing that
// must be able to zeroize that material on demand.
//
// Two responsibilities:
//
//	POST /keyscope        seal a conversation scope seed with this node's chip secret
//	GET  /keyscope/<id>   report which slots hold material and which are destroyed
//	POST /destruction     verify the coordinator + customer signatures, zeroize this
//	                      node's key material for the scope, return a signed receipt
//
// Nothing here trusts the caller for correctness: the destroy request must carry a
// valid coordinator signature and a valid customer authorization, verified against
// the configured JWKS before any material is touched.
package operatorsurface

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"nexqloud-sealed/internal/derive/material"
	"nexqloud-sealed/internal/derive/state"
	"nexqloud-sealed/internal/erasure/destroy"
	"nexqloud-sealed/internal/erasure/destruction"
	"nexqloud-sealed/internal/keyscope"
	"nexqloud-sealed/internal/registry"
)

// Config describes one operator node.
type Config struct {
	Registry   *registry.HTTPClient
	OperatorID string
	// StateDir holds the node's local wrap cache and ciphertext files that a
	// destruction overwrites.
	StateDir string
	// CallbackURL is how a coordinator can reach this node to dispatch a
	// destruction (e.g. https://<edge>/v1/d/<endpoint>). It is registered with the
	// node's wrap so the coordinator can address deployments without a
	// hand-maintained operator map.
	CallbackURL string
}

// Register attaches the operator surface to a mux.
//
// The surface is served twice: at the bare paths, and under /v1. The public edge
// rewrites /v1/d/<endpoint>/X to /v1/X before the request reaches the shim, so a
// coordinator addressing a deployment as https://<edge>/v1/d/<endpoint> ends up on
// the /v1 aliases. Serving both means one binary works standalone and behind the
// edge with no edge change.
func Register(mux *http.ServeMux, cfg Config) {
	for _, prefix := range []string{"", "/v1"} {
		mux.HandleFunc(prefix+"/destruction", handleDestruction(cfg))
		mux.HandleFunc(prefix+"/keyscope", handleKeyScope(cfg))
		mux.HandleFunc(prefix+"/keyscope/", handleKeyScopeStatus(cfg))
	}
	log.Printf("operator surface enabled as %q (registry %s)", cfg.OperatorID, cfg.Registry.BaseURL)
}

// scopeIDFromPath strips whichever surface prefix the request arrived on.
func scopeIDFromPath(path string) string {
	for _, prefix := range []string{"/v1/keyscope/", "/keyscope/"} {
		if strings.HasPrefix(path, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(path, prefix))
		}
	}
	return ""
}

// handleDestruction is the endpoint the destruction coordinator dispatches to. The
// heavy lifting lives in internal/erasure/destroy, which verifies both signatures
// and produces the receipts.
func handleDestruction(cfg Config) http.HandlerFunc {
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
		var req destruction.SignedDestroyReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		rcpt, err := destroy.Destroy(req, req.TenantID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		log.Printf("destruction %s: zeroized material for tenant %s, receipt signed", req.DestructionID, req.TenantID)

		// The coordinator embeds the aggregator's submit URL in the dispatch, so the
		// node pushes its evidence without needing to know the aggregator itself.
		if req.AggregatorSubmitURL != "" {
			payload, err := json.Marshal(rcpt)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			submitReq, buildErr := http.NewRequest(http.MethodPost, req.AggregatorSubmitURL, bytes.NewReader(payload))
			if buildErr != nil {
				http.Error(w, buildErr.Error(), http.StatusBadGateway)
				return
			}
			submitReq.Header.Set("Content-Type", "application/json")
			// Same shared secret as the registry: the aggregator gates writes from the
			// public edge, so receipts must carry it.
			if token := strings.TrimSpace(os.Getenv("NEXQLOUD_REGISTRY_TOKEN")); token != "" {
				submitReq.Header.Set("X-Sealed-Registry-Token", token)
			}
			resp, err := http.DefaultClient.Do(submitReq)
			if err != nil {
				http.Error(w, fmt.Sprintf("submit receipt: %v", err), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				http.Error(
					w,
					fmt.Sprintf("aggregator %s: %s", resp.Status, strings.TrimSpace(string(respBody))),
					http.StatusBadGateway,
				)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(rcpt)
	}
}

type keyScopeRequest struct {
	ScopeID    string `json:"scope_id"`
	SeedHex    string `json:"seed_hex"`
	KeyVersion int    `json:"key_version"`
}

type keyScopeResponse struct {
	ScopeID    string `json:"scope_id"`
	OperatorID string `json:"operator_id"`
	SeedCommit string `json:"seed_commit"`
	// SeedHex is only returned when this node generated the seed, so the caller can
	// register the same seed with the peer nodes and then discard it.
	SeedHex   string `json:"seed_hex,omitempty"`
	Generated bool   `json:"generated"`
	WrapBytes int    `json:"wrap_bytes"`
}

// handleKeyScope seals a scope seed with this node's chip secret and registers the
// sealed copy in the registry. Every node holds its own sealed copy of the same
// seed, so a scope keeps cross-node key continuity while becoming individually
// destroyable.
func handleKeyScope(cfg Config) http.HandlerFunc {
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
		var req keyScopeRequest
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

		generated := false
		existingSlot := false
		seed, err := keyscope.ParseSeed(req.SeedHex)
		if err != nil {
			if strings.TrimSpace(req.SeedHex) != "" {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Idempotent registration. If this node already holds a slot for the scope, reuse
			// that seed: the registry refuses to overwrite live key material (an overwrite
			// would rotate the conversation's DEK and make stored ciphertext unopenable), so a
			// repeat registration used to end as a 502 — and every refresh, new tab or second
			// turn re-registers. Returning the existing seed makes the call safe to retry.
			resolver := &keyscope.Resolver{Client: cfg.Registry, OperatorID: cfg.OperatorID, Chip: material.Chip}
			if prior, perr := resolver.Seed(scopeID); perr == nil {
				seed = prior
				existingSlot = true
			} else if !strings.Contains(perr.Error(), keyscope.ErrNoKeyMaterial.Error()) {
				http.Error(w, "resolve existing key material: "+perr.Error(), http.StatusInternalServerError)
				return
			}
			if !existingSlot {
				seed, err = keyscope.NewSeed()
				if err != nil {
					http.Error(w, "generate seed", http.StatusInternalServerError)
					return
				}
				generated = true
			}
		}

		chipSecret, err := material.Chip()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		wrap := state.Seal(chipSecret, seed)
		seedCommit := keyscope.SeedCommit(seed)

		if !existingSlot {
			if err := cfg.Registry.PutWrap(scopeID, cfg.OperatorID, wrap, seedCommit); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		}
		// Record how this node can be reached, so the coordinator does not need a
		// hand-maintained operator map. Best effort: a scope with material but no
		// callback still destroys correctly when the map is configured.
		if cfg.CallbackURL != "" {
			if err := cfg.Registry.PutCallback(scopeID, cfg.OperatorID, cfg.CallbackURL); err != nil {
				log.Printf("keyscope %s: could not register callback url for %s: %v", scopeID, cfg.OperatorID, err)
			}
		}

		resp := keyScopeResponse{
			ScopeID:    scopeID,
			OperatorID: cfg.OperatorID,
			SeedCommit: seedCommit,
			Generated:  generated,
			WrapBytes:  len(wrap),
		}
		if generated {
			resp.SeedHex = hex.EncodeToString(seed)
		}

		state.Zeroize(seed)
		state.Zeroize(wrap)
		state.Zeroize(chipSecret)

		log.Printf("keyscope %s registered by %s (commit %s, generated=%v)", scopeID, cfg.OperatorID, seedCommit, generated)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(resp)
	}
}

type keyScopeStatus struct {
	ScopeID    string   `json:"scope_id"`
	SeedCommit string   `json:"seed_commit"`
	Operators  []string `json:"operators"`
	Destroyed  []string `json:"destroyed"`
}

// handleKeyScopeStatus reports who holds material for a scope and which slots have
// been destroyed. The record is shared, so every node reports the same view.
func handleKeyScopeStatus(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scopeID := scopeIDFromPath(r.URL.Path)
		if scopeID == "" {
			http.Error(w, "scope_id is required", http.StatusBadRequest)
			return
		}

		record, err := cfg.Registry.Get(scopeID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		status := keyScopeStatus{
			ScopeID:    record.TenantID,
			SeedCommit: record.SeedCommit,
			Operators:  []string{},
			Destroyed:  []string{},
		}
		for op, wrap := range record.Wraps {
			if len(wrap) == 0 {
				status.Destroyed = append(status.Destroyed, op)
				continue
			}
			status.Operators = append(status.Operators, op)
		}
		sort.Strings(status.Operators)
		sort.Strings(status.Destroyed)

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(status)
	}
}

// EnvOr reads an environment variable with a fallback, so both binaries share the
// same configuration conventions.
func EnvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

var _ = keyscope.ErrNoKeyMaterial
