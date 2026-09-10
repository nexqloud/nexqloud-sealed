package chatstate

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"nexqloud-sealed/internal/derive/state"
)

var ErrInvalidPayload = errors.New("invalid encrypted_payload")

type Message struct {
	Role      string `json:"role"`
	Content   string `json:"content"`
	ReceiptID string `json:"receipt_id,omitempty"`
}

type State struct {
	Messages []Message `json:"messages"`
}

func Open(dek []byte, encoded string) (*State, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return &State{}, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidPayload
	}
	plaintext, err := state.Open(dek, raw)
	state.Zeroize(raw)
	if err != nil {
		return nil, ErrInvalidPayload
	}
	defer state.Zeroize(plaintext)

	var st State
	if err := json.Unmarshal(plaintext, &st); err != nil {
		return nil, ErrInvalidPayload
	}
	return &st, nil
}

func Seal(dek []byte, st *State) (string, error) {
	if st == nil {
		st = &State{}
	}
	plaintext, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	defer state.Zeroize(plaintext)

	blob := state.Seal(dek, plaintext)
	defer state.Zeroize(blob)
	return base64.StdEncoding.EncodeToString(blob), nil
}
