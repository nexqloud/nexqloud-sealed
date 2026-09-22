// Package documents holds the sealed form of a customer document and of the page
// images rendered from it.
//
// Everything here is ciphertext. The plaintext of a document exists only inside
// the enclave, and the key that opens these envelopes is derived there from the
// four-part material — customer claim, chip secret, federation seed and
// attestation binding — by internal/derive/kdf. Nothing in this package ever
// hands a key back to a caller.
//
// The envelope is deliberately self-describing: a few bytes of header sit
// outside the AEAD so a reader knows what it is holding and which key version to
// derive before it opens anything. Those bytes are unauthenticated, and that is
// safe here: the key version selects the DEK, so a tampered version can only
// make an envelope fail to open, never open wrongly.
package documents

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"nexqloud-sealed/internal/derive/state"
)

const (
	envelopeMagic = "NSD1"
	headerLen     = len(envelopeMagic) + 4 + 1
)

// Kind says what a sealed envelope holds.
type Kind byte

const (
	// KindSource is the document as the customer sent it.
	KindSource Kind = 1
	// KindPage is one rendered page image of that document.
	KindPage Kind = 2
)

func (k Kind) String() string {
	switch k {
	case KindSource:
		return "source"
	case KindPage:
		return "page"
	default:
		return fmt.Sprintf("kind(%d)", byte(k))
	}
}

var (
	ErrNotSealed    = errors.New("documents: not a sealed document")
	ErrWrongVersion = errors.New("documents: envelope key version does not match the derived key")
	ErrMissingKey   = errors.New("documents: missing key material")
)

// Fingerprint names a document by the SHA-256 of its plaintext. It is stable
// across re-uploads, which is what makes "the same bytes were sent twice"
// answerable without storing either copy.
func Fingerprint(plaintext []byte) string {
	sum := sha256.Sum256(plaintext)
	return hex.EncodeToString(sum[:])
}

// Seal returns magic|key_version|kind|state.Seal(dek, plaintext).
func Seal(dek []byte, keyVersion int, kind Kind, plaintext []byte) ([]byte, error) {
	if len(dek) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("%w: key is %d bytes, want %d", ErrMissingKey, len(dek), chacha20poly1305.KeySize)
	}
	if keyVersion <= 0 {
		return nil, fmt.Errorf("documents: invalid key version %d", keyVersion)
	}
	if kind != KindSource && kind != KindPage {
		return nil, fmt.Errorf("documents: invalid kind %s", kind)
	}

	envelope := make([]byte, 0, headerLen+len(plaintext)+28)
	envelope = append(envelope, envelopeMagic...)
	envelope = binary.BigEndian.AppendUint32(envelope, uint32(keyVersion))
	envelope = append(envelope, byte(kind))
	envelope = append(envelope, state.Seal(dek, plaintext)...)
	return envelope, nil
}

// Header reads what an envelope says about itself without opening it. It needs no
// key: the key version is what tells the caller which key to derive.
func Header(envelope []byte) (keyVersion int, kind Kind, err error) {
	keyVersion, kind, _, err = split(envelope)
	return keyVersion, kind, err
}

// Open opens an envelope sealed under keyVersion. A mismatch is refused rather
// than attempted, because deriving a different key can only fail the tag and
// would hide which of the two things went wrong.
func Open(dek, envelope []byte, keyVersion int) (Kind, []byte, error) {
	version, kind, body, err := split(envelope)
	if err != nil {
		return 0, nil, err
	}
	if version != keyVersion {
		return 0, nil, fmt.Errorf("%w: envelope v%d, key v%d", ErrWrongVersion, version, keyVersion)
	}
	if len(dek) != chacha20poly1305.KeySize {
		return 0, nil, fmt.Errorf("%w: key is %d bytes, want %d", ErrMissingKey, len(dek), chacha20poly1305.KeySize)
	}

	plaintext, err := state.Open(dek, body)
	if err != nil {
		return 0, nil, fmt.Errorf("documents: open %s: %w", kind, err)
	}
	return kind, plaintext, nil
}

// Sealed is one document: its stable name, the key version it is sealed under,
// the sealed source and the sealed page renders. A caller stores these bytes
// anywhere — object storage outside the enclosure is the intended home — and can
// open none of them.
type Sealed struct {
	Fingerprint string
	KeyVersion  int
	Source      []byte
	Pages       [][]byte
}

// PageCount is how many page renders the document carries.
func (s Sealed) PageCount() int { return len(s.Pages) }

// SealDocument seals a source document and its rendered pages under one key.
func SealDocument(dek []byte, keyVersion int, source []byte, pages [][]byte) (Sealed, error) {
	if len(source) == 0 {
		return Sealed{}, errors.New("documents: empty source")
	}

	sealedSource, err := Seal(dek, keyVersion, KindSource, source)
	if err != nil {
		return Sealed{}, err
	}

	out := Sealed{
		Fingerprint: Fingerprint(source),
		KeyVersion:  keyVersion,
		Source:      sealedSource,
		Pages:       make([][]byte, 0, len(pages)),
	}
	for i, page := range pages {
		if len(page) == 0 {
			return Sealed{}, fmt.Errorf("documents: page %d is empty", i+1)
		}
		envelope, err := Seal(dek, keyVersion, KindPage, page)
		if err != nil {
			return Sealed{}, fmt.Errorf("documents: page %d: %w", i+1, err)
		}
		out.Pages = append(out.Pages, envelope)
	}
	return out, nil
}

// OpenDocument opens a sealed document. It refuses an envelope whose recorded
// kind is not what the caller is asking for, so a page image can never be passed
// off as the source document or the other way round.
func OpenDocument(dek []byte, s Sealed) (source []byte, pages [][]byte, err error) {
	kind, source, err := Open(dek, s.Source, s.KeyVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("documents: source: %w", err)
	}
	if kind != KindSource {
		return nil, nil, fmt.Errorf("%w: expected source, found %s", ErrNotSealed, kind)
	}

	pages = make([][]byte, 0, len(s.Pages))
	for i, envelope := range s.Pages {
		kind, page, err := Open(dek, envelope, s.KeyVersion)
		if err != nil {
			return nil, nil, fmt.Errorf("documents: page %d: %w", i+1, err)
		}
		if kind != KindPage {
			return nil, nil, fmt.Errorf("%w: page %d is %s, not a page", ErrNotSealed, i+1, kind)
		}
		pages = append(pages, page)
	}
	return source, pages, nil
}

func split(envelope []byte) (keyVersion int, kind Kind, body []byte, err error) {
	if len(envelope) <= headerLen {
		return 0, 0, nil, ErrNotSealed
	}
	if string(envelope[:len(envelopeMagic)]) != envelopeMagic {
		return 0, 0, nil, ErrNotSealed
	}
	rest := envelope[len(envelopeMagic):]
	keyVersion = int(binary.BigEndian.Uint32(rest[:4]))
	kind = Kind(rest[4])
	if keyVersion <= 0 || (kind != KindSource && kind != KindPage) {
		return 0, 0, nil, fmt.Errorf("%w: bad header (v%d, %s)", ErrNotSealed, keyVersion, kind)
	}
	return keyVersion, kind, rest[5:], nil
}
