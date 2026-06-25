package inference

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type VLLM struct {
	baseURL string
	client  *http.Client
}

func NewVLLM(baseURL string) *VLLM {
	return &VLLM{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 120 * time.Second},
	}
}

func (v *VLLM) Complete(req Request) (Response, error) {
	body, err := json.Marshal(struct {
		Model    string    `json:"model"`
		Messages []Message `json:"messages"`
	}{
		Model:    req.Model,
		Messages: req.Messages,
	})
	if err != nil {
		return Response{}, err
	}

	url := v.baseURL + "/v1/chat/completions"
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("vllm request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return Response{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("vllm status %d: %s", resp.StatusCode, string(raw))
	}

	var parsed struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Response{}, fmt.Errorf("vllm decode: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return Response{}, fmt.Errorf("vllm: empty choices")
	}

	model := parsed.Model
	if model == "" {
		model = req.Model
	}

	return Response{
		Content: parsed.Choices[0].Message.Content,
		Model:   model,
	}, nil
}
