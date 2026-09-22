package readkey

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func recipient(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate recipient: %v", err)
	}
	return key
}

func issue(t *testing.T, pub *ecdh.PublicKey) *Grant {
	t.Helper()
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	grant, err := Issue(pub, "doc-fingerprint", PurposeReview, 3, 2, 5*time.Minute, now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return grant
}

func TestIssueHandsTheBrowserAKeyItCanOpenAndNobodyElseCan(t *testing.T) {
	browser := recipient(t)
	grant := issue(t, browser.PublicKey())

	// The browser recovers exactly the session key the enclave kept.
	opened, err := Open(browser, grant.Wrapped)
	if err != nil {
		t.Fatalf("Open with the addressed recipient: %v", err)
	}
	if !bytes.Equal(opened, grant.Key) {
		t.Fatal("the browser recovered a different session key")
	}

	// Somebody else's browser, holding the grant, gets nothing.
	other := recipient(t)
	if _, err := Open(other, grant.Wrapped); !errors.Is(err, ErrGrant) {
		t.Fatalf("a foreign recipient opened the grant: %v", err)
	}
}

func TestGrantCarriesNoPlaintextSessionKey(t *testing.T) {
	grant := issue(t, recipient(t).PublicKey())

	raw, err := json.Marshal(grant.Wrapped)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, grant.Key) {
		t.Fatal("the session key is in the grant in the clear")
	}
	if strings.Contains(string(raw), base64.StdEncoding.EncodeToString(grant.Key)) {
		t.Fatal("the session key is in the grant base64-encoded")
	}

	// What travels is public: the ephemeral half, a salt, a nonce.
	decoded, err := base64.StdEncoding.DecodeString(grant.Wrapped.Ephemeral)
	if err != nil {
		t.Fatalf("ephemeral key is not decodable: %v", err)
	}
	if len(decoded) != 65 {
		t.Fatalf("ephemeral public key is %d bytes, want an uncompressed P-256 point", len(decoded))
	}
	if _, err := ecdh.P256().NewPublicKey(decoded); err != nil {
		t.Fatalf("ephemeral key is not a P-256 point: %v", err)
	}
}

func TestAGrantNamesTheBrowserItWasAddressedTo(t *testing.T) {
	browser := recipient(t)
	grant := issue(t, browser.PublicKey())

	if grant.Wrapped.RecipientSHA256 == "" {
		t.Fatal("the grant does not record who it was addressed to")
	}
	if grant.Wrapped.DocumentID != "doc-fingerprint" || grant.Wrapped.Purpose != PurposeReview {
		t.Fatalf("grant lost the document or the purpose: %+v", grant.Wrapped)
	}
	if grant.Wrapped.KeyVersion != 3 || grant.Wrapped.Pages != 2 {
		t.Fatalf("grant lost the version or the page count: %+v", grant.Wrapped)
	}
	if grant.Wrapped.Schema != Schema {
		t.Fatalf("schema = %q", grant.Wrapped.Schema)
	}
	if !grant.Wrapped.ExpiresAt.Equal(time.Date(2026, 9, 22, 12, 5, 0, 0, time.UTC)) {
		t.Fatalf("expiry = %v", grant.Wrapped.ExpiresAt)
	}
	if grant.Wrapped.TTLSeconds != 300 {
		t.Fatalf("ttl = %d", grant.Wrapped.TTLSeconds)
	}
}

func TestEveryGrantIsItsOwnKey(t *testing.T) {
	browser := recipient(t)
	first := issue(t, browser.PublicKey())
	second := issue(t, browser.PublicKey())

	if bytes.Equal(first.Key, second.Key) {
		t.Fatal("two grants reused a session key")
	}
	if first.Wrapped.Ephemeral == second.Wrapped.Ephemeral {
		t.Fatal("two grants reused an ephemeral key")
	}
	// Both open: the recipient is what binds a grant, not one-time state.
	if _, err := Open(browser, second.Wrapped); err != nil {
		t.Fatalf("second grant: %v", err)
	}
}

func TestTamperedGrantIsRefusedRatherThanOpenedWrongly(t *testing.T) {
	browser := recipient(t)
	grant := issue(t, browser.PublicKey())

	cases := map[string]func(w *Wrapped){
		"session key byte flipped": func(w *Wrapped) { w.SessionKey = flipBase64(t, w.SessionKey) },
		"nonce flipped":            func(w *Wrapped) { w.Nonce = flipBase64(t, w.Nonce) },
		"salt flipped":             func(w *Wrapped) { w.Salt = flipBase64(t, w.Salt) },
		"ephemeral swapped":        func(w *Wrapped) { w.Ephemeral = base64.StdEncoding.EncodeToString(recipient(t).PublicKey().Bytes()) },
		"schema from elsewhere":    func(w *Wrapped) { w.Schema = "sealed-read-key/2" },
		"truncated session key":    func(w *Wrapped) { w.SessionKey = "AAAA" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			broken := grant.Wrapped
			mutate(&broken)
			key, err := Open(browser, broken)
			if err == nil {
				t.Fatalf("opened a tampered grant into %d bytes", len(key))
			}
		})
	}
}

func flipBase64(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	raw[0] ^= 0xff
	base64.StdEncoding.Encode(out, raw)
	return string(out)
}

func TestSessionKeyOpensThePagesItWasIssuedFor(t *testing.T) {
	grant := issue(t, recipient(t).PublicKey())
	page := []byte("\x89PNG\r\n\x1a\n the plaintext of a customs form, page one")

	sealed, err := SealPage(grant.Key, page)
	if err != nil {
		t.Fatalf("SealPage: %v", err)
	}
	if bytes.Contains(sealed, page) {
		t.Fatal("the sealed page contains the page")
	}
	if bytes.HasPrefix(sealed, []byte("\x89PNG")) {
		t.Fatal("a sealed page still looks like a page image")
	}

	opened, err := OpenPage(grant.Key, sealed)
	if err != nil {
		t.Fatalf("OpenPage: %v", err)
	}
	if !bytes.Equal(opened, page) {
		t.Fatal("the page did not come back")
	}

	t.Run("another session key cannot open it", func(t *testing.T) {
		if _, err := OpenPage(issue(t, recipient(t).PublicKey()).Key, sealed); err == nil {
			t.Fatal("a foreign session key opened the page")
		}
	})

	t.Run("a flipped byte cannot be opened", func(t *testing.T) {
		broken := bytes.Clone(sealed)
		broken[len(broken)-1] ^= 0xff
		if _, err := OpenPage(grant.Key, broken); err == nil {
			t.Fatal("a tampered page opened")
		}
	})

	t.Run("the page seal is not the wrap", func(t *testing.T) {
		// Both descend from the session key; neither may be read as the other.
		asAWrapper := append(mustDecode(t, grant.Wrapped.Nonce), mustDecode(t, grant.Wrapped.SessionKey)...)
		if _, err := OpenPage(grant.Key, asAWrapper); err == nil {
			t.Fatal("a key wrap opened as a page")
		}
		if _, err := OpenPage(grant.Key, append(mustDecode(t, grant.Wrapped.Salt), []byte("...")...)); err == nil {
			t.Fatal("the wrap salt opened as a page")
		}
	})
}

func TestShortKeysAreRefusedNotPanicked(t *testing.T) {
	if _, err := SealPage([]byte("short"), []byte("page")); !errors.Is(err, ErrKeySize) {
		t.Fatalf("SealPage with a short key: %v", err)
	}
	if _, err := OpenPage([]byte("short"), []byte("sealed")); !errors.Is(err, ErrKeySize) {
		t.Fatalf("OpenPage with a short key: %v", err)
	}
	if _, err := SealPage(nil, []byte("page")); !errors.Is(err, ErrKeySize) {
		t.Fatalf("SealPage with no key: %v", err)
	}
}

func TestOnlyReviewGetsAKey(t *testing.T) {
	pub := recipient(t).PublicKey()
	for _, purpose := range []string{"extract", "download", "admin", ""} {
		if _, err := Issue(pub, "doc", purpose, 1, 1, time.Minute, time.Now()); !errors.Is(err, ErrPurpose) {
			t.Fatalf("purpose %q was issued a key: %v", purpose, err)
		}
	}
}

func TestALifetimeBeyondTheBoundsIsCutToTheBounds(t *testing.T) {
	cases := map[int]time.Duration{
		0:      DefaultTTL,
		-30:    DefaultTTL,
		5:      MinTTL,
		300:    5 * time.Minute,
		100000: MaxTTL,
	}
	for seconds, want := range cases {
		if got := ClampTTL(seconds); got != want {
			t.Fatalf("ClampTTL(%d) = %v, want %v", seconds, got, want)
		}
	}
}

func TestIssueClampsWhatTheCallerAskedFor(t *testing.T) {
	now := time.Now()
	grant, err := Issue(recipient(t).PublicKey(), "doc", PurposeReview, 1, 1, time.Hour, now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if grant.Wrapped.TTLSeconds != int(MaxTTL.Seconds()) {
		t.Fatalf("ttl = %d seconds, want the maximum", grant.Wrapped.TTLSeconds)
	}
	if !grant.ExpiresAt.Before(now.Add(time.Hour)) {
		t.Fatal("the grant outlived the maximum")
	}
}

func TestRecipientKeysAreValidated(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(recipient(t).PublicKey().Bytes())
	if _, err := ParseRecipient(good); err != nil {
		t.Fatalf("a real P-256 public key was refused: %v", err)
	}

	junk := make([]byte, 65)
	if _, err := rand.Read(junk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	cases := map[string]string{
		"empty":           "",
		"not base64":      "not base64!!",
		"too short":       base64.StdEncoding.EncodeToString([]byte("12345")),
		"not a point":     base64.StdEncoding.EncodeToString(junk),
		"a private key":   base64.StdEncoding.EncodeToString(recipient(t).Bytes()),
		"the wrong curve": base64.StdEncoding.EncodeToString([]byte{0x04, 0x01, 0x02}),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRecipient(encoded); !errors.Is(err, ErrRecipient) {
				t.Fatalf("err = %v, want ErrRecipient", err)
			}
		})
	}

	if _, err := Issue(nil, "doc", PurposeReview, 1, 1, time.Minute, time.Now()); !errors.Is(err, ErrRecipient) {
		t.Fatalf("Issue with no recipient: %v", err)
	}
}

func mustDecode(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return raw
}
