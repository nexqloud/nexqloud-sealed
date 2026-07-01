package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Client interface {
	Get(tenantID string) (CommitmentRecord, error)
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
