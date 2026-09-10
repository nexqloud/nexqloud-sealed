package chat

import (
	"errors"
	"fmt"
	"strings"

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
		return TurnResult{
			Content:          out.Content,
			Model:            out.Model,
			EncryptedPayload: blob,
		}, fmt.Errorf("receipt sealer not configured")
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
		return TurnResult{
			Content:          out.Content,
			Model:            out.Model,
			EncryptedPayload: blob,
		}, fmt.Errorf("receipt: %w", err)
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

	return TurnResult{
		Content:          out.Content,
		Model:            out.Model,
		EncryptedPayload: blob,
		ReceiptID:        receiptID,
		Receipt:          sealed,
	}, nil
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
