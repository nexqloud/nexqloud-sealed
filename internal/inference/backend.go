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

	// JSONSchema constrains the model's output to this schema. With it the model
	// cannot emit a structurally wrong answer, so a caller does not have to detect
	// a malformed one after the fact.
	JSONSchema string `json:"json_schema,omitempty"`
	// Grammar is the same idea in the engine's own grammar language (GBNF for
	// llama.cpp), for constraints a JSON schema cannot express.
	Grammar string `json:"grammar,omitempty"`
	// Logprobs asks the engine to report what probability it gave each token it
	// wrote. That is what turns a self-reported confidence into a measured one.
	Logprobs    bool `json:"logprobs,omitempty"`
	TopLogprobs int  `json:"top_logprobs,omitempty"`

	// DisableThinking asks the engine not to deliberate before answering. A reasoning
	// model spends its token budget on hidden reasoning first, and the caller's budget
	// is spent before any answer text exists: a document read comes back empty with
	// finish_reason=length. A read wants a constrained answer, not a monologue, so the
	// document path sets this and chat leaves it alone.
	DisableThinking bool `json:"-"`
}

// TokenLogprob is the engine's own opinion of one token it wrote.
type TokenLogprob struct {
	Token   string  `json:"token"`
	Logprob float64 `json:"logprob"`
}

type Response struct {
	Content string
	Model   string
	// TokenLogprobs is filled only when the request asked for logprobs. Empty
	// means "not measured", never "measured as zero".
	TokenLogprobs []TokenLogprob
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
