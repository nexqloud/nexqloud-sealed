package inference

import "strings"

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Request struct {
	Model            string    `json:"model"`
	Prompt           string    `json:"prompt,omitempty"`
	Messages         []Message `json:"messages,omitempty"`
	EncryptedPayload string    `json:"encrypted_payload,omitempty"`
	Stream           bool      `json:"stream,omitempty"`
	JWTToken         string    `json:"jwt_token,omitempty"`
	TenantID         string    `json:"tenant_id,omitempty"`
	ChallengeNonce   string    `json:"challenge_nonce,omitempty"`
	Temperature      *float64  `json:"temperature,omitempty"`
	MaxTokens        *int      `json:"max_tokens,omitempty"`
}

type Response struct {
	Content string
	Model   string
}

type TokenHandler func(token string) error

type Backend interface {
	Complete(req Request) (Response, error)
}

type Streamer interface {
	CompleteStream(req Request, emit TokenHandler) (Response, error)
}

func PromptFrom(req Request) string {
	if p := strings.TrimSpace(req.Prompt); p != "" {
		return p
	}
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" && strings.TrimSpace(req.Messages[i].Content) != "" {
			return req.Messages[i].Content
		}
	}
	if len(req.Messages) > 0 {
		return req.Messages[len(req.Messages)-1].Content
	}
	return ""
}
