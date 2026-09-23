package inference

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type VLLM struct {
	baseURL string
	client  *http.Client
	// Dialect is which engine is behind the endpoint. Empty means llama.cpp, the
	// engine the sealed guests actually run.
	Dialect Dialect
}

// Dialect names the serving engine. The two engines offer the same capabilities
// under different field names, and a request shaped for the wrong one is silently
// ignored rather than rejected — the constraint just does not apply.
type Dialect string

const (
	DialectLlamaCpp Dialect = "llama.cpp"
	DialectVLLM     Dialect = "vllm"
)

func (v *VLLM) dialect() Dialect {
	if v.Dialect == DialectVLLM {
		return DialectVLLM
	}
	return DialectLlamaCpp
}

// contentParts builds the content array for a multimodal read: the words first, then each page
// picture as a data URL, in the order the pages came.
//
// This is the shape llama.cpp's server reads images in from a model with a vision projector. The
// pictures are base64 in the request body, so they never touch disk and never leave the enclosure.
func contentParts(prompt string, images []Image) []map[string]any {
	parts := make([]map[string]any, 0, len(images)+1)
	parts = append(parts, map[string]any{"type": "text", "text": prompt})
	for _, image := range images {
		mimeType := strings.TrimSpace(image.MIMEType)
		if mimeType == "" {
			mimeType = "image/png"
		}
		parts = append(parts, map[string]any{
			"type": "image_url",
			"image_url": map[string]any{
				"url": "data:" + mimeType + ";base64," + base64.StdEncoding.EncodeToString(image.Data),
			},
		})
	}
	return parts
}

func NewVLLM(baseURL string) *VLLM {
	return &VLLM{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 120 * time.Second},
	}
}

func (v *VLLM) Complete(req Request) (Response, error) {
	return v.complete(req, false, nil)
}

func (v *VLLM) CompleteStream(req Request, emit TokenHandler) (Response, error) {
	return v.complete(req, true, emit)
}

func (v *VLLM) complete(req Request, stream bool, emit TokenHandler) (Response, error) {
	payload := map[string]any{
		"model":  req.Model,
		"stream": stream,
	}
	// messages must be an array: an OpenAI-compatible server rejects a null before the
	// engine ever reads the prompt. A document read is built as a plain prompt rather
	// than a conversation, so it becomes the single user turn of one — without this a
	// document extraction dies with a 400 while chat, which always fills Messages,
	// keeps working.
	switch {
	case len(req.Images) > 0:
		// A read of a document with no text layer: the words and the page pictures travel in
		// one user turn. An engine served without a vision projector rejects the request
		// rather than ignoring the pictures, which is the failure worth having — a read that
		// silently went text-only would answer from nothing.
		payload["messages"] = []map[string]any{{
			"role":    "user",
			"content": contentParts(req.Prompt, req.Images),
		}}
	case len(req.Messages) > 0:
		payload["messages"] = req.Messages
	case strings.TrimSpace(req.Prompt) != "":
		payload["messages"] = []Message{{Role: "user", Content: req.Prompt}}
	default:
		payload["messages"] = []Message{}
	}
	if req.DisableThinking {
		// A model that deliberates before answering puts its reasoning on the same
		// token budget, and llama.cpp keeps that reasoning out of the content field —
		// so a capped read comes back empty with finish_reason=length. The kwarg goes
		// to the chat template; a template that has no such switch ignores it.
		payload["chat_template_kwargs"] = map[string]any{"enable_thinking": false}
	}
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	if req.MaxTokens != nil {
		payload["max_tokens"] = *req.MaxTokens
	}
	if err := v.applyOutputConstraints(payload, req); err != nil {
		return Response{}, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, err
	}

	url := v.baseURL + "/v1/chat/completions"
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if stream {
		httpReq.Header.Set("Accept", "text/event-stream")
	}

	resp, err := v.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("vllm request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return Response{}, fmt.Errorf("vllm status %d: %s", resp.StatusCode, string(raw))
	}

	if stream {
		return readStream(resp.Body, req.Model, emit)
	}
	return readJSON(resp.Body, req.Model)
}

// applyOutputConstraints adds a grammar and a logprobs request when the caller
// asked for them. The schema is what keeps a document extraction structurally
// correct: the engine is constrained to the shape rather than merely asked for it.
func (v *VLLM) applyOutputConstraints(payload map[string]any, req Request) error {
	if req.JSONSchema != "" {
		if !json.Valid([]byte(req.JSONSchema)) {
			return fmt.Errorf("inference: json_schema is not valid json")
		}
		key := "guided_json"
		if v.dialect() == DialectLlamaCpp {
			key = "json_schema"
		}
		payload[key] = json.RawMessage(req.JSONSchema)
	}
	if req.Grammar != "" {
		key := "guided_grammar"
		if v.dialect() == DialectLlamaCpp {
			key = "grammar"
		}
		payload[key] = req.Grammar
	}
	if req.Logprobs {
		payload["logprobs"] = true
		if req.TopLogprobs > 0 {
			payload["top_logprobs"] = req.TopLogprobs
		}
	}
	return nil
}

func readJSON(r io.Reader, fallbackModel string) (Response, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return Response{}, err
	}
	return parseCompletionJSON(raw, fallbackModel)
}

func parseCompletionJSON(raw []byte, fallbackModel string) (Response, error) {
	var parsed struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Logprobs struct {
				Content []struct {
					Token   string  `json:"token"`
					Logprob float64 `json:"logprob"`
				} `json:"content"`
			} `json:"logprobs"`
			Text string `json:"text"`
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
		model = fallbackModel
	}
	content := parsed.Choices[0].Message.Content
	if content == "" {
		content = parsed.Choices[0].Text
	}

	// Built by append so that "the engine measured nothing" stays a nil slice: a
	// caller must never read an absent measurement as a confident zero.
	var tokens []TokenLogprob
	for _, tok := range parsed.Choices[0].Logprobs.Content {
		tokens = append(tokens, TokenLogprob{Token: tok.Token, Logprob: tok.Logprob})
	}

	return Response{
		Content:       content,
		Model:         model,
		TokenLogprobs: tokens,
	}, nil
}

func readStream(r io.Reader, fallbackModel string, emit TokenHandler) (Response, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var full strings.Builder
	var leftover strings.Builder
	model := fallbackModel
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "event:") || strings.HasPrefix(line, ":") {
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			leftover.WriteString(line)
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var chunk struct {
			Model   string `json:"model"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
				Text string `json:"text"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			leftover.WriteString(payload)
			continue
		}
		if chunk.Model != "" {
			model = chunk.Model
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		token := chunk.Choices[0].Delta.Content
		if token == "" {
			token = chunk.Choices[0].Text
		}
		if token == "" && full.Len() == 0 {
			token = chunk.Choices[0].Message.Content
		}
		if token == "" {
			continue
		}
		full.WriteString(token)
		if emit != nil {
			if err := emit(token); err != nil {
				if full.Len() > 0 {
					log.Printf("inference stream emit: %v", err)
					return Response{Content: full.String(), Model: model}, nil
				}
				return Response{}, fmt.Errorf("inference stream: %w", err)
			}
		}
	}
	if err := scanner.Err(); err != nil && full.Len() == 0 && leftover.Len() == 0 {
		return Response{}, fmt.Errorf("inference stream: %w", err)
	}
	if full.Len() == 0 && leftover.Len() > 0 {
		out, err := parseCompletionJSON([]byte(leftover.String()), model)
		if err != nil {
			if scanner.Err() != nil {
				return Response{}, fmt.Errorf("inference stream: %w", scanner.Err())
			}
			return Response{}, err
		}
		if emit != nil && out.Content != "" {
			_ = emit(out.Content)
		}
		return out, nil
	}
	if err := scanner.Err(); err != nil {
		log.Printf("inference stream ended: %v", err)
	}
	return Response{Content: full.String(), Model: model}, nil
}
