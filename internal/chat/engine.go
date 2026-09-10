package chat

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"unicode/utf8"

	"nexqloud-sealed/internal/chatstate"
	"nexqloud-sealed/internal/derive/kdf"
	"nexqloud-sealed/internal/derive/material"
	"nexqloud-sealed/internal/derive/state"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/receipt"
)

type Sealer func(in receipt.Input) (*receipt.SealedReceipt, error)

type Materials struct {
	Seed       []byte
	Chip       []byte
	AttestBind []byte
	KeyVersion int
}

type Engine struct {
	Inference inference.Backend
	Seal      Sealer
	Materials Materials
}

type TurnResult struct {
	Content          string
	Model            string
	EncryptedPayload string
	ReceiptID        string
	Receipt          *receipt.SealedReceipt
}

func (e *Engine) deriveDEK(id identity.VerifiedIdentity) ([]byte, error) {
	tenantID := strings.TrimSpace(id.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("missing tenant_id")
	}
	if len(id.ClaimDigest) == 0 {
		return nil, fmt.Errorf("missing claim digest")
	}
	version := e.Materials.KeyVersion
	if version == 0 {
		version = material.KeyVersion
	}
	return kdf.DeriveDEK(e.Materials.Seed, e.Materials.Chip, id.ClaimDigest, e.Materials.AttestBind, tenantID, version)
}

func (e *Engine) Decrypt(id identity.VerifiedIdentity, encoded string) ([]chatstate.Message, error) {
	dek, err := e.deriveDEK(id)
	if err != nil {
		return nil, err
	}
	defer state.Zeroize(dek)

	st, err := chatstate.Open(dek, encoded)
	if err != nil {
		return nil, err
	}
	logOpenedThread("history", id, encoded, st.Messages)
	return st.Messages, nil
}

func (e *Engine) Turn(id identity.VerifiedIdentity, req inference.Request, emit inference.TokenHandler) (TurnResult, error) {
	prompt := inference.PromptFrom(req)
	if strings.TrimSpace(prompt) == "" {
		return TurnResult{}, fmt.Errorf("missing prompt")
	}

	dek, err := e.deriveDEK(id)
	if err != nil {
		return TurnResult{}, err
	}
	defer state.Zeroize(dek)

	st, err := chatstate.Open(dek, req.EncryptedPayload)
	if err != nil {
		return TurnResult{}, err
	}
	logOpenedThread("turn", id, req.EncryptedPayload, st.Messages)

	st.Messages = append(st.Messages, chatstate.Message{Role: "user", Content: prompt})

	inferReq := inference.Request{
		Model:       req.Model,
		Messages:    toInferenceMessages(st.Messages),
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
	}

	out, err := e.infer(inferReq, emit)
	if err != nil {
		return TurnResult{}, fmt.Errorf("inference: %w", err)
	}

	st.Messages = append(st.Messages, chatstate.Message{
		Role:    "assistant",
		Content: out.Content,
	})

	if e.Seal == nil {
		blob, sealErr := chatstate.Seal(dek, st)
		if sealErr != nil {
			return TurnResult{Content: out.Content, Model: out.Model}, fmt.Errorf("receipt sealer not configured")
		}
		return e.finishTurn(id, TurnResult{
			Content:          out.Content,
			Model:            out.Model,
			EncryptedPayload: blob,
		}, len(st.Messages), fmt.Errorf("receipt sealer not configured"))
	}
	sealed, err := e.Seal(receipt.Input{
		Prompt:            prompt,
		Response:          out.Content,
		ChallengeNonce:    req.ChallengeNonce,
		IdentityClaimHash: id.Hash,
	})
	if err != nil {
		blob, sealErr := chatstate.Seal(dek, st)
		if sealErr != nil {
			return TurnResult{Content: out.Content, Model: out.Model}, fmt.Errorf("receipt: %w", err)
		}
		return e.finishTurn(id, TurnResult{
			Content:          out.Content,
			Model:            out.Model,
			EncryptedPayload: blob,
		}, len(st.Messages), fmt.Errorf("receipt: %w", err))
	}

	receiptID := ""
	if sealed != nil {
		receiptID = sealed.Package.ReceiptID
	}
	st.Messages[len(st.Messages)-1].ReceiptID = receiptID

	blob, err := chatstate.Seal(dek, st)
	if err != nil {
		return TurnResult{
			Content:   out.Content,
			Model:     out.Model,
			ReceiptID: receiptID,
			Receipt:   sealed,
		}, fmt.Errorf("chatstate: %w", err)
	}

	return e.finishTurn(id, TurnResult{
		Content:          out.Content,
		Model:            out.Model,
		EncryptedPayload: blob,
		ReceiptID:        receiptID,
		Receipt:          sealed,
	}, len(st.Messages), nil)
}

func (e *Engine) infer(req inference.Request, emit inference.TokenHandler) (inference.Response, error) {
	if emit != nil {
		if streamer, ok := e.Inference.(inference.Streamer); ok {
			return streamer.CompleteStream(req, emit)
		}
		out, err := e.Inference.Complete(req)
		if err != nil {
			return inference.Response{}, err
		}
		if out.Content != "" {
			if err := emit(out.Content); err != nil {
				return inference.Response{}, err
			}
		}
		return out, nil
	}
	return e.Inference.Complete(req)
}

func (e *Engine) finishTurn(id identity.VerifiedIdentity, out TurnResult, threadLen int, err error) (TurnResult, error) {
	LogOutboundReply("turn", id.TenantID, out.Model, out.ReceiptID, out.Content, out.EncryptedPayload, threadLen)
	return out, err
}

func logOpenedThread(kind string, id identity.VerifiedIdentity, ciphertext string, msgs []chatstate.Message) {
	n := len(msgs)
	bytes := len(strings.TrimSpace(ciphertext))
	tenant := strings.TrimSpace(id.TenantID)
	if bytes == 0 {
		log.Printf("[sealed] decrypt (%s): tenant=%s no ciphertext — new thread (plaintext exists only inside the TEE)", kind, tenant)
		return
	}
	log.Printf("[sealed] decrypt (%s): tenant=%s ciphertext=%dB unsealed inside TEE → %d message(s)", kind, tenant, bytes, n)
	log.Printf("[sealed] decrypt (%s): DEK derived in-enclave from identity+chip+measurement", kind)
	if n == 0 {
		log.Printf("[sealed] decrypt (%s): blob opened but thread is empty", kind)
		return
	}
	for i, m := range msgs {
		log.Printf("[sealed] decrypt (%s):   #%d %s: %s", kind, i+1, m.Role, clipLog(m.Content, 240))
	}
}

func LogOutboundReply(kind, tenant, model, receiptID, content, ciphertext string, threadLen int) {
	tenant = strings.TrimSpace(tenant)
	log.Printf("[sealed] reply (%s): tenant=%s model=%s receipt=%s", kind, tenant, model, receiptID)
	log.Printf("[sealed] reply (%s): sending assistant plaintext to client: %s", kind, clipLog(content, 240))
	log.Printf("[sealed] reply (%s): re-encrypted %d message(s) → ciphertext=%dB", kind, threadLen, len(strings.TrimSpace(ciphertext)))
}

func clipLog(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if max <= 0 || utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max]) + "…"
}

func toInferenceMessages(msgs []chatstate.Message) []inference.Message {
	out := make([]inference.Message, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, inference.Message{Role: m.Role, Content: m.Content})
	}
	return out
}

func IsInvalidPayload(err error) bool {
	return errors.Is(err, chatstate.ErrInvalidPayload)
}
