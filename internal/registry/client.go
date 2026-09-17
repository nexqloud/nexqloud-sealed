package registry

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Client interface {
	Get(tenantID string) (CommitmentRecord, error)
}

// Writer is the mutation surface of a registry. Callers type-assert a Client to
// Writer, so read-only clients, mocks and existing tests keep working unchanged.
//
// PutWrap registers (or re-seals) one operator's key material for a key scope.
// DestroyWrap zeroes it and keeps the operator's slot, which is what makes a
// destruction durable: without it the registry would still hold the wrap and an
// operator restart would refetch the material that was supposedly erased. The
// slot is kept so the verifier can still reconstruct the destruction quorum.
type Writer interface {
	PutWrap(tenantID, operatorID string, wrap []byte, seedCommit string) error
	DestroyWrap(tenantID, operatorID string) error
}

type HTTPClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewHTTPClient(baseURL string) *HTTPClient {
	return &HTTPClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: http.DefaultClient,
	}
}

func (c *HTTPClient) Get(tenantID string) (CommitmentRecord, error) {
	if tenantID == "" {
		return CommitmentRecord{}, fmt.Errorf("tenant_id is required")
	}

	url := fmt.Sprintf("%s/records/%s", c.BaseURL, tenantID)
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return CommitmentRecord{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return CommitmentRecord{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return CommitmentRecord{}, fmt.Errorf("record not found for tenant %q", tenantID)
	}
	if resp.StatusCode != http.StatusOK {
		return CommitmentRecord{}, fmt.Errorf("registry %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var record CommitmentRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return CommitmentRecord{}, fmt.Errorf("decode record: %w", err)
	}
	return record, nil
}

// PutWrap registers one operator's sealed key material for a key scope.
func (c *HTTPClient) PutWrap(tenantID, operatorID string, wrap []byte, seedCommit string) error {
	if tenantID == "" || operatorID == "" {
		return fmt.Errorf("tenant_id and operator_id are required")
	}
	if len(wrap) == 0 {
		return fmt.Errorf("wrap is required")
	}

	payload, err := json.Marshal(map[string]any{
		"operator_id": operatorID,
		"seed_commit": seedCommit,
		"wrap":        base64.StdEncoding.EncodeToString(wrap),
	})
	if err != nil {
		return err
	}

	return c.do(http.MethodPut, c.wrapURL(tenantID, operatorID), payload)
}

// DestroyWrap zeroes one operator's key material for a key scope, keeping the
// operator's slot in the record so the destruction quorum stays auditable.
func (c *HTTPClient) DestroyWrap(tenantID, operatorID string) error {
	if tenantID == "" || operatorID == "" {
		return fmt.Errorf("tenant_id and operator_id are required")
	}
	return c.do(http.MethodDelete, c.wrapURL(tenantID, operatorID), nil)
}

func (c *HTTPClient) wrapURL(tenantID, operatorID string) string {
	return fmt.Sprintf("%s/records/%s/wraps/%s", c.BaseURL, tenantID, operatorID)
}

func (c *HTTPClient) do(method, url string, payload []byte) error {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("registry %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}
