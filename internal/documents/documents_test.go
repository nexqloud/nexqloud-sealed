package documents

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func testKey(t *testing.T, fill byte) []byte {
	t.Helper()
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = fill
	}
	return key
}

const sourceDoc = "CBP 7501 ENTRY SUMMARY\nEntry 7501-2025-0402\nHTS 8207301500\nDuty paid 29440.00 USD\n"
const pageOne = "\x89PNG\r\n\x1a\nfake page render one"
const pageTwo = "\x89PNG\r\n\x1a\nfake page render two"

func TestFingerprintIsThePlaintextHash(t *testing.T) {
	sum := sha256.Sum256([]byte(sourceDoc))
	want := hex.EncodeToString(sum[:])

	if got := Fingerprint([]byte(sourceDoc)); got != want {
		t.Fatalf("Fingerprint = %s, want %s", got, want)
	}
	if Fingerprint([]byte(sourceDoc)) != Fingerprint([]byte(sourceDoc)) {
		t.Fatal("Fingerprint is not stable across calls")
	}
	if Fingerprint([]byte(sourceDoc)) == Fingerprint([]byte(sourceDoc+" ")) {
		t.Fatal("Fingerprint collided for different plaintext")
	}
}

func TestRoundTripDocument(t *testing.T) {
	dek := testKey(t, 0x11)

	sealed, err := SealDocument(dek, 1, []byte(sourceDoc), [][]byte{[]byte(pageOne), []byte(pageTwo)})
	if err != nil {
		t.Fatalf("SealDocument: %v", err)
	}
	if sealed.PageCount() != 2 {
		t.Fatalf("PageCount = %d, want 2", sealed.PageCount())
	}
	if sealed.Fingerprint != Fingerprint([]byte(sourceDoc)) {
		t.Fatalf("Fingerprint = %s, want the source hash", sealed.Fingerprint)
	}

	source, pages, err := OpenDocument(dek, sealed)
	if err != nil {
		t.Fatalf("OpenDocument: %v", err)
	}
	if string(source) != sourceDoc {
		t.Fatalf("source round-trip = %q", source)
	}
	if len(pages) != 2 || string(pages[0]) != pageOne || string(pages[1]) != pageTwo {
		t.Fatalf("pages round-trip = %q", pages)
	}
}

func TestSealedBytesCarryNoPlaintext(t *testing.T) {
	dek := testKey(t, 0x22)

	sealed, err := SealDocument(dek, 3, []byte(sourceDoc), [][]byte{[]byte(pageOne)})
	if err != nil {
		t.Fatalf("SealDocument: %v", err)
	}

	for name, blob := range map[string][]byte{"source": sealed.Source, "page": sealed.Pages[0]} {
		if bytes.Contains(blob, []byte("8207301500")) || bytes.Contains(blob, []byte("29440.00")) {
			t.Fatalf("%s envelope leaks plaintext", name)
		}
		if bytes.Contains(blob, []byte("PNG")) {
			t.Fatalf("%s envelope leaks page bytes", name)
		}
	}
}

func TestHeaderNeedsNoKey(t *testing.T) {
	dek := testKey(t, 0x33)

	sealed, err := SealDocument(dek, 7, []byte(sourceDoc), [][]byte{[]byte(pageOne)})
	if err != nil {
		t.Fatalf("SealDocument: %v", err)
	}

	version, kind, err := Header(sealed.Source)
	if err != nil {
		t.Fatalf("Header(source): %v", err)
	}
	if version != 7 || kind != KindSource {
		t.Fatalf("Header(source) = v%d %s, want v7 source", version, kind)
	}

	version, kind, err = Header(sealed.Pages[0])
	if err != nil {
		t.Fatalf("Header(page): %v", err)
	}
	if version != 7 || kind != KindPage {
		t.Fatalf("Header(page) = v%d %s, want v7 page", version, kind)
	}
}

func TestOpenRefusesWrongKeyVersion(t *testing.T) {
	dek := testKey(t, 0x44)

	envelope, err := Seal(dek, 1, KindSource, []byte(sourceDoc))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, _, err := Open(dek, envelope, 2); !errors.Is(err, ErrWrongVersion) {
		t.Fatalf("Open with wrong version = %v, want ErrWrongVersion", err)
	}
	// Same key material, right version: opens. Version is bound into the
	// derivation, not into the ciphertext only.
	if _, _, err := Open(dek, envelope, 1); err != nil {
		t.Fatalf("Open with right version: %v", err)
	}
}

func TestOpenRefusesWrongKeyAndTamperedCiphertext(t *testing.T) {
	dek := testKey(t, 0x55)
	other := testKey(t, 0x66)

	envelope, err := Seal(dek, 1, KindSource, []byte(sourceDoc))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, _, err := Open(other, envelope, 1); err == nil {
		t.Fatal("Open with a different key succeeded")
	}

	tampered := bytes.Clone(envelope)
	tampered[len(tampered)-1] ^= 0xff
	if _, _, err := Open(dek, tampered, 1); err == nil {
		t.Fatal("Open of a tampered ciphertext succeeded")
	}
}

func TestOpenRefusesForeignBytes(t *testing.T) {
	dek := testKey(t, 0x77)

	cases := map[string][]byte{
		"empty":         nil,
		"too short":     []byte("NSD1"),
		"wrong magic":   append([]byte("XXXX"), make([]byte, 40)...),
		"plain pdf":     []byte("%PDF-1.3 not sealed at all"),
		"truncated hdr": []byte("NSD1\x00\x00\x00\x01"),
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Open(dek, blob, 1); err == nil {
				t.Fatal("Open accepted bytes that are not a sealed document")
			}
			if _, _, err := Header(blob); err == nil {
				t.Fatal("Header accepted bytes that are not a sealed document")
			}
		})
	}
}

func TestKindIsEnforcedAcrossTheEnvelope(t *testing.T) {
	dek := testKey(t, 0x88)

	// A page image must not be openable as the source document, even with the
	// right key and the right version.
	pageEnvelope, err := Seal(dek, 1, KindPage, []byte(pageOne))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, _, err = OpenDocument(dek, Sealed{KeyVersion: 1, Source: pageEnvelope})
	if !errors.Is(err, ErrNotSealed) {
		t.Fatalf("OpenDocument with a page as source = %v, want ErrNotSealed", err)
	}

	sourceEnvelope, err := Seal(dek, 1, KindSource, []byte(sourceDoc))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, _, err = OpenDocument(dek, Sealed{KeyVersion: 1, Source: sourceEnvelope, Pages: [][]byte{sourceEnvelope}})
	if !errors.Is(err, ErrNotSealed) {
		t.Fatalf("OpenDocument with a source as page = %v, want ErrNotSealed", err)
	}
}

func TestSealRejectsBadInput(t *testing.T) {
	dek := testKey(t, 0x99)

	if _, err := Seal([]byte("short"), 1, KindSource, []byte(sourceDoc)); !errors.Is(err, ErrMissingKey) {
		t.Fatalf("Seal with a short key = %v, want ErrMissingKey", err)
	}
	if _, err := Seal(dek, 0, KindSource, []byte(sourceDoc)); err == nil {
		t.Fatal("Seal accepted key version 0")
	}
	if _, err := Seal(dek, 1, Kind(9), []byte(sourceDoc)); err == nil {
		t.Fatal("Seal accepted an unknown kind")
	}
	if _, err := SealDocument(dek, 1, nil, nil); err == nil {
		t.Fatal("SealDocument accepted an empty source")
	}
	if _, err := SealDocument(dek, 1, []byte(sourceDoc), [][]byte{{}}); err == nil {
		t.Fatal("SealDocument accepted an empty page")
	}
}

func TestOpenWithShortKeyIsReportedNotPanicked(t *testing.T) {
	envelope, err := Seal(testKey(t, 0xaa), 1, KindSource, []byte(sourceDoc))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Open panicked on a short key: %v", r)
		}
	}()
	if _, _, err := Open([]byte("short"), envelope, 1); !errors.Is(err, ErrMissingKey) {
		t.Fatalf("Open with a short key = %v, want ErrMissingKey", err)
	}
}

func TestKindString(t *testing.T) {
	if KindSource.String() != "source" || KindPage.String() != "page" {
		t.Fatal("Kind.String is wrong")
	}
	if !strings.Contains(Kind(9).String(), "9") {
		t.Fatal("unknown Kind.String should show its number")
	}
}
