package destruction

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"crypto/ed25519"

	"github.com/google/uuid"

	"nexqloud-sealed/internal/registry"
)

type DispatchResult struct {
	OperatorID string `json:"operator_id"`
	Status     string `json:"status"`
	Detail     string `json:"detail,omitempty"`
}

type Session struct {
	DestructionID string           `json:"destruction_id"`
	TenantID      string           `json:"tenant_id"`
	KeyVersion    int              `json:"key_version"`
	SeedCommit    string           `json:"seed_commit"`
	Quorum        []string         `json:"quorum"`
	Status        string           `json:"status"`
	Dispatches    []DispatchResult `json:"dispatches"`
	CreatedAt     string           `json:"created_at"`
}

type Coordinator struct {
	Registry      registry.Client
	Aggregator    string
	OperatorURL   map[string]string
	HTTPClient    *http.Client
	JWKSURL       string
	CoordinatorSK ed25519.PrivateKey

	mu       sync.RWMutex
	sessions map[string]Session
}

func NewCoordinator(reg registry.Client, aggregatorURL string, operatorURLs map[string]string) *Coordinator {
	return &Coordinator{
		Registry:    reg,
		Aggregator:  strings.TrimRight(aggregatorURL, "/"),
		OperatorURL: operatorURLs,
		HTTPClient:  http.DefaultClient,
		sessions:    make(map[string]Session),
	}
}

func (c *Coordinator) SetAuth(jwksURL string, coordinatorSK ed25519.PrivateKey) {
	c.JWKSURL = strings.TrimSpace(jwksURL)
	c.CoordinatorSK = coordinatorSK
}

type CreateDestructionRequest struct {
	TenantID    string `json:"tenant_id"`
	CustomerSig []byte `json:"customer_sig"`
	Nonce       string `json:"nonce"`
}

type registerAggregatorRequest struct {
	DestructionID string   `json:"destruction_id"`
	TenantID      string   `json:"tenant_id"`
	Quorum        []string `json:"quorum"`
	SeedCommit    string   `json:"seed_commit"`
	KeyVersion    int      `json:"key_version"`
}

func (c *Coordinator) CreateDestruction(ctx context.Context, req CreateDestructionRequest) (Session, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return Session{}, fmt.Errorf("tenant_id is required")
	}

	if c.JWKSURL != "" {
		if err := acceptDeleteRequest(tenantID, req.CustomerSig, req.Nonce, c.JWKSURL); err != nil {
			return Session{}, err
		}
	}

	quorum, err := Quorum(c.Registry, tenantID)
	if err != nil {
		return Session{}, err
	}
	if len(quorum) == 0 {
		return Session{}, fmt.Errorf("no operators in quorum for tenant %q", tenantID)
	}

	rec, err := c.Registry.Get(tenantID)
	if err != nil {
		return Session{}, err
	}

	destructionID := uuid.NewString()
	session := Session{
		DestructionID: destructionID,
		TenantID:      tenantID,
		KeyVersion:    rec.KeyVersion,
		SeedCommit:    rec.SeedCommit,
		Quorum:        quorum,
		Status:        "pending",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	if err := c.registerWithAggregator(ctx, session); err != nil {
		return Session{}, fmt.Errorf("register with aggregator: %w", err)
	}

	dispatches := make([]DispatchResult, 0, len(quorum))
	overallOK := true
	for _, opID := range quorum {
		result := c.dispatchToOperator(ctx, session, opID, req.CustomerSig)
		dispatches = append(dispatches, result)
		if result.Status != "dispatched" {
			overallOK = false
		}
	}
	session.Dispatches = dispatches
	if overallOK {
		session.Status = "dispatched"
	} else {
		session.Status = "partial"
	}

	c.mu.Lock()
	c.sessions[destructionID] = session
	c.mu.Unlock()

	return session, nil
}

func (c *Coordinator) GetSession(destructionID string) (Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.sessions[destructionID]
	return s, ok
}

func (c *Coordinator) registerWithAggregator(ctx context.Context, session Session) error {
	body := registerAggregatorRequest{
		DestructionID: session.DestructionID,
		TenantID:      session.TenantID,
		Quorum:        session.Quorum,
		SeedCommit:    session.SeedCommit,
		KeyVersion:    session.KeyVersion,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	url := c.Aggregator + "/destructions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aggregator %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func (c *Coordinator) dispatchToOperator(ctx context.Context, session Session, operatorID string, customerSig []byte) DispatchResult {
	baseURL, ok := c.OperatorURL[operatorID]
	if !ok || strings.TrimSpace(baseURL) == "" {
		return DispatchResult{
			OperatorID: operatorID,
			Status:     "skipped",
			Detail:     "operator URL not configured",
		}
	}

	req := SignedDestroyReq{
		DestructionID:       session.DestructionID,
		TenantID:            session.TenantID,
		KeyVersion:          session.KeyVersion,
		SeedCommit:          session.SeedCommit,
		OperatorID:          operatorID,
		AggregatorSubmitURL: fmt.Sprintf("%s/destructions/%s/receipts", c.Aggregator, session.DestructionID),
		CustomerSig:         customerSig,
	}
	if len(c.CoordinatorSK) == ed25519.PrivateKeySize {
		sig, err := SignDispatch(c.CoordinatorSK, req)
		if err != nil {
			return DispatchResult{OperatorID: operatorID, Status: "failed", Detail: err.Error()}
		}
		req.CoordinatorSig = sig
	}

	body, err := json.Marshal(req)
	if err != nil {
		return DispatchResult{OperatorID: operatorID, Status: "failed", Detail: err.Error()}
	}

	url := strings.TrimRight(baseURL, "/") + "/destruction"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return DispatchResult{OperatorID: operatorID, Status: "failed", Detail: err.Error()}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return DispatchResult{OperatorID: operatorID, Status: "failed", Detail: err.Error()}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return DispatchResult{
			OperatorID: operatorID,
			Status:     "failed",
			Detail:     fmt.Sprintf("%s: %s", resp.Status, strings.TrimSpace(string(respBody))),
		}
	}
	return DispatchResult{OperatorID: operatorID, Status: "dispatched"}
}

func ParseOperatorURLs(spec string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		id := strings.TrimSpace(kv[0])
		url := strings.TrimSpace(kv[1])
		if id != "" && url != "" {
			out[id] = url
		}
	}
	return out
}
