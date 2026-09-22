// Package readkey issues a short-lived, session-scoped key that opens one
// document's page renders.
//
// The problem it solves: the review screen shows a page to a human, but the
// application serving that screen must not be able to read the document. Handing
// the application a key fails — it would hold it. So the key is wrapped to a public
// key the reviewer's browser generated and keeps to itself: the enclave never sees
// the browser's private half, the application cannot open what it relays, and the
// only party who can read a page render is the browser it was addressed to.
//
// The primitives are the ones a browser already has: ECDH on P-256, HKDF-SHA256 and
// AES-256-GCM, all native to WebCrypto. The boundary's internal envelopes stay on
// XChaCha20-Poly1305; adding a hand-written XChaCha implementation to a browser
// security path would be a worse trade than using the platform's own.
//
// What a grant is worth, honestly:
//
//   - Scope is enforced by cryptography. A session key opens this grant's page
//     renders and nothing else — not the document source, not another grant, not
//     another tenant's anything.
//   - Time is not. A key already in a browser cannot be taken back by a clock, so
//     the expiry is a recorded promise the caller honours, not an enforcement
//     point. What makes the promise meaningful is that the grant is receipted.
package readkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

const (
	// Schema names the grant's shape so a reader can refuse a version it does not
	// understand instead of guessing.
	Schema = "sealed-read-key/1"

	// SessionKeySize is the length of a session key, in bytes.
	SessionKeySize = 32

	// NonceSize is the AES-GCM nonce length. It is prepended to what it seals,
	// matching the rest of this codebase's envelopes.
	NonceSize = 12

	// PurposeReview is the only purpose this door issues keys for today. An
	// unlisted purpose is refused rather than quietly treated as a read.
	PurposeReview = "review"

	// Bounds on a requested lifetime. Long enough for a reviewer to work through a
	// case, short enough that a forgotten tab is not an open door.
	MinTTL = 30 * time.Second
	MaxTTL = 15 * time.Minute
	// DefaultTTL applies when the caller asks for nothing.
	DefaultTTL = 5 * time.Minute

	// Distinct context strings keep the wrap and the page seals in separate
	// cryptographic domains even though both use the session key's material.
	wrapInfo = "sealed-read-key/1|wrap"
	pageInfo = "sealed-read-key/1|page"
)

var (
	ErrRecipient = errors.New("readkey: recipient public key is not usable")
	ErrGrant     = errors.New("readkey: grant cannot be opened")
	ErrPurpose   = errors.New("readkey: unsupported purpose")
	ErrKeySize   = errors.New("readkey: session key must be 32 bytes")
)

// Wrapped is the session key sealed to one recipient, plus what the recipient
// needs to open it. It travels in the clear: the ephemeral public half, a salt and
// a nonce are all public by construction, and the session key itself cannot be
// recovered from them without the recipient's private half.
type Wrapped struct {
	Schema          string    `json:"schema"`
	DocumentID      string    `json:"document_id"`
	Purpose         string    `json:"purpose"`
	KeyVersion      int       `json:"key_version"`
	Pages           int       `json:"pages"`
	RecipientSHA256 string    `json:"recipient_sha256"`
	Ephemeral       string    `json:"ephemeral_public_key"`
	Salt            string    `json:"salt"`
	Nonce           string    `json:"nonce"`
	SessionKey      string    `json:"wrapped_session_key"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	TTLSeconds      int       `json:"ttl_seconds"`
}

// ParseRecipient turns a browser's encoded public key into something that can be
// used to wrap a key. A key that is not a valid P-256 point on the curve is
// refused here rather than producing a grant nobody can open.
func ParseRecipient(encoded string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecipient, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrRecipient)
	}
	key, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecipient, err)
	}
	return key, nil
}

// NewSessionKey returns a random session key.
func NewSessionKey() ([]byte, error) {
	key := make([]byte, SessionKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("readkey: session key: %w", err)
	}
	return key, nil
}

// Grant is one issued read key.
type Grant struct {
	Key       []byte
	Purpose   string
	ExpiresAt time.Time
	TTL       time.Duration
	Wrapped   Wrapped
}

// ClampTTL keeps a requested lifetime inside the bounds this door will issue for.
// Zero means "the caller has no preference" and gets the default.
func ClampTTL(seconds int) time.Duration {
	if seconds <= 0 {
		return DefaultTTL
	}
	ttl := time.Duration(seconds) * time.Second
	if ttl < MinTTL {
		return MinTTL
	}
	if ttl > MaxTTL {
		return MaxTTL
	}
	return ttl
}

// Issue generates a session key for one document and wraps it to the recipient.
// The session key never leaves this process in the clear.
func Issue(recipient *ecdh.PublicKey, documentID, purpose string, keyVersion, pages int, ttl time.Duration, now time.Time) (*Grant, error) {
	if purpose != PurposeReview {
		return nil, fmt.Errorf("%w: %q", ErrPurpose, purpose)
	}
	if recipient == nil {
		return nil, ErrRecipient
	}
	if ttl < MinTTL {
		ttl = MinTTL
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}

	sessionKey, err := NewSessionKey()
	if err != nil {
		return nil, err
	}

	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("readkey: ephemeral key: %w", err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecipient, err)
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("readkey: salt: %w", err)
	}
	wrapKey, err := hkdf.Key(sha256.New, shared, salt, wrapInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("readkey: wrap key: %w", err)
	}

	sealed, err := sealWith(wrapKey, sessionKey)
	if err != nil {
		return nil, err
	}

	recipientSHA := sha256.Sum256(recipient.Bytes())
	expires := now.Add(ttl)

	return &Grant{
		Key:       sessionKey,
		Purpose:   purpose,
		ExpiresAt: expires,
		TTL:       ttl,
		Wrapped: Wrapped{
			Schema:          Schema,
			DocumentID:      documentID,
			Purpose:         purpose,
			KeyVersion:      keyVersion,
			Pages:           pages,
			RecipientSHA256: fmt.Sprintf("%x", recipientSHA),
			Ephemeral:       base64.StdEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
			Salt:            base64.StdEncoding.EncodeToString(salt),
			Nonce:           base64.StdEncoding.EncodeToString(sealed[:NonceSize]),
			SessionKey:      base64.StdEncoding.EncodeToString(sealed[NonceSize:]),
			IssuedAt:        now.UTC(),
			ExpiresAt:       expires.UTC(),
			TTLSeconds:      int(ttl.Seconds()),
		},
	}, nil
}

// Open recovers a session key with the recipient's private half. It exists so a
// client — and this package's own tests — can be held to the same contract the
// browser will implement, rather than trusting that the wrap round-trips.
func Open(recipient *ecdh.PrivateKey, w Wrapped) ([]byte, error) {
	if recipient == nil {
		return nil, ErrRecipient
	}
	if w.Schema != Schema {
		return nil, fmt.Errorf("%w: schema %q", ErrGrant, w.Schema)
	}
	ephemeralRaw, err := base64.StdEncoding.DecodeString(w.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral key: %v", ErrGrant, err)
	}
	ephemeral, err := ecdh.P256().NewPublicKey(ephemeralRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral key: %v", ErrGrant, err)
	}
	shared, err := recipient.ECDH(ephemeral)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGrant, err)
	}
	salt, err := base64.StdEncoding.DecodeString(w.Salt)
	if err != nil {
		return nil, fmt.Errorf("%w: salt: %v", ErrGrant, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(w.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce: %v", ErrGrant, err)
	}
	body, err := base64.StdEncoding.DecodeString(w.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: session key: %v", ErrGrant, err)
	}
	wrapKey, err := hkdf.Key(sha256.New, shared, salt, wrapInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: wrap key: %v", ErrGrant, err)
	}

	sealed := append(append([]byte{}, nonce...), body...)
	key, err := openWith(wrapKey, sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGrant, err)
	}
	if len(key) != SessionKeySize {
		return nil, fmt.Errorf("%w: opened %d bytes", ErrKeySize, len(key))
	}
	return key, nil
}

// SealPage seals one page render under a session key.
func SealPage(sessionKey, page []byte) ([]byte, error) {
	if len(sessionKey) != SessionKeySize {
		return nil, fmt.Errorf("%w: %d", ErrKeySize, len(sessionKey))
	}
	return sealWithSession(sessionKey, pageInfo, page)
}

// OpenPage opens a page render sealed by SealPage.
func OpenPage(sessionKey, sealed []byte) ([]byte, error) {
	if len(sessionKey) != SessionKeySize {
		return nil, fmt.Errorf("%w: %d", ErrKeySize, len(sessionKey))
	}
	return openWithSession(sessionKey, pageInfo, sealed)
}

// sealWithSession seals bytes under a key derived from the session key, with its
// own context string, so a page seal and a key wrap can never be confused for one
// another even though both descend from the same secret.
func sealWithSession(sessionKey []byte, info string, plaintext []byte) ([]byte, error) {
	derived, err := hkdf.Key(sha256.New, sessionKey, nil, info, 32)
	if err != nil {
		return nil, fmt.Errorf("readkey: derive %s key: %w", info, err)
	}
	return sealWith(derived, plaintext)
}

func openWithSession(sessionKey []byte, info string, sealed []byte) ([]byte, error) {
	derived, err := hkdf.Key(sha256.New, sessionKey, nil, info, 32)
	if err != nil {
		return nil, fmt.Errorf("readkey: derive %s key: %w", info, err)
	}
	return openWith(derived, sealed)
}

func sealWith(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("readkey: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func openWith(key, sealed []byte) ([]byte, error) {
	if len(sealed) <= NonceSize {
		return nil, ErrGrant
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, sealed[:NonceSize], sealed[NonceSize:], nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: %d", ErrKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("readkey: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("readkey: %w", err)
	}
	return gcm, nil
}
