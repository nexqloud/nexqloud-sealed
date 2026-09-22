// Package docwire is the wire format for a sealed document moving between the
// enclave and its caller.
//
// A document is a source file plus its page renders. Base64 inside JSON would
// inflate every byte by a third and make a forty-page case unpleasant, so the
// bytes travel raw: a small header says what the parts are, then the parts follow
// in order. The header is not trusted — each part carries the digest of the bytes
// that follows it, and the reader verifies every one before handing them on.
//
// Header layout:
//
//	"NSDW"          4 bytes, magic
//	uint32 BE       header length
//	header JSON     UTF-8, describes the parts
//	part bytes      source first, then each page, in the order the header lists them
package docwire

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// Magic leads every container.
	Magic = "NSDW"
	// Schema names the header's shape, so a reader can refuse a version it does
	// not understand instead of guessing.
	Schema = "sealed-document/1"
	// ContentType is what a container is served as.
	ContentType = "application/vnd.nexqloud.sealed-document"

	MaxHeaderBytes = 1 << 20   // 1 MiB of header is already absurd
	MaxPartBytes   = 512 << 20 // per part
	MaxTotalBytes  = 1 << 30   // whole container
)

var (
	ErrNotDocwire     = errors.New("docwire: not a document container")
	ErrDigestMismatch = errors.New("docwire: part digest does not match its bytes")
	ErrTooLarge       = errors.New("docwire: container exceeds the size limit")
)

// Part describes one blob in the container.
type Part struct {
	Name   string `json:"name"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Header describes a container. Only ciphertext travels in one, so the header is
// metadata: what the document is called, which key version sealed it, and what
// the caller should expect to find.
type Header struct {
	Schema       string          `json:"schema"`
	DocumentID   string          `json:"document_id"`
	KeyVersion   int             `json:"key_version"`
	DetectedType string          `json:"detected_type,omitempty"`
	Source       Part            `json:"source"`
	Pages        []Part          `json:"pages,omitempty"`
	ReceiptID    string          `json:"receipt_id,omitempty"`
	Receipt      json.RawMessage `json:"sealed_receipt,omitempty"`
	Error        string          `json:"error,omitempty"`
}

// PageCount is how many page renders the container carries.
func (h Header) PageCount() int { return len(h.Pages) }

// TotalBytes is the sum of every part's length.
func (h Header) TotalBytes() int {
	total := h.Source.Bytes
	for _, p := range h.Pages {
		total += p.Bytes
	}
	return total
}

// Encode writes header, source and pages as one container. The part names, sizes
// and digests are computed here from the bytes actually written, so a caller
// cannot describe a container that says something other than what it holds.
func Encode(w io.Writer, h Header, source []byte, pages [][]byte) error {
	if len(source) == 0 {
		return errors.New("docwire: empty source")
	}
	if len(source) > MaxPartBytes {
		return fmt.Errorf("%w: source is %d bytes", ErrTooLarge, len(source))
	}

	total := int64(len(source))
	parts := make([]Part, 0, len(pages))
	for i, page := range pages {
		if len(page) == 0 {
			return fmt.Errorf("docwire: page %d is empty", i+1)
		}
		if len(page) > MaxPartBytes {
			return fmt.Errorf("%w: page %d is %d bytes", ErrTooLarge, i+1, len(page))
		}
		total += int64(len(page))
		parts = append(parts, describe(fmt.Sprintf("page-%03d", i+1), page))
	}
	if total > MaxTotalBytes {
		return fmt.Errorf("%w: %d bytes", ErrTooLarge, total)
	}

	h.Schema = Schema
	h.Source = describe("source", source)
	h.Pages = parts

	header, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("docwire: encode header: %w", err)
	}
	if len(header) > MaxHeaderBytes {
		return fmt.Errorf("%w: header is %d bytes", ErrTooLarge, len(header))
	}

	if _, err := io.WriteString(w, Magic); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(header))); err != nil {
		return err
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(source); err != nil {
		return err
	}
	for _, page := range pages {
		if _, err := w.Write(page); err != nil {
			return err
		}
	}
	return nil
}

// Decode reads a container and verifies every part against its digest. It returns
// the header, the source and the pages in the order the header listed them.
func Decode(r io.Reader) (Header, []byte, [][]byte, error) {
	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return Header{}, nil, nil, fmt.Errorf("%w: %v", ErrNotDocwire, err)
	}
	if string(magic) != Magic {
		return Header{}, nil, nil, ErrNotDocwire
	}

	var headerLen uint32
	if err := binary.Read(r, binary.BigEndian, &headerLen); err != nil {
		return Header{}, nil, nil, fmt.Errorf("%w: header length: %v", ErrNotDocwire, err)
	}
	if headerLen == 0 || headerLen > MaxHeaderBytes {
		return Header{}, nil, nil, fmt.Errorf("%w: header length %d", ErrNotDocwire, headerLen)
	}

	raw := make([]byte, headerLen)
	if _, err := io.ReadFull(r, raw); err != nil {
		return Header{}, nil, nil, fmt.Errorf("%w: truncated header: %v", ErrNotDocwire, err)
	}

	var h Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return Header{}, nil, nil, fmt.Errorf("%w: header json: %v", ErrNotDocwire, err)
	}
	if h.Schema != Schema {
		return Header{}, nil, nil, fmt.Errorf("%w: schema %q", ErrNotDocwire, h.Schema)
	}

	described := append([]Part{h.Source}, h.Pages...)
	blobs := make([][]byte, 0, len(described))
	total := 0
	for i, part := range described {
		if part.Bytes <= 0 || part.Bytes > MaxPartBytes {
			return Header{}, nil, nil, fmt.Errorf("%w: part %d declares %d bytes", ErrNotDocwire, i, part.Bytes)
		}
		total += part.Bytes
		if total > MaxTotalBytes {
			return Header{}, nil, nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, total)
		}

		blob := make([]byte, part.Bytes)
		if _, err := io.ReadFull(r, blob); err != nil {
			return Header{}, nil, nil, fmt.Errorf("%w: part %s: %v", ErrNotDocwire, part.Name, err)
		}
		if part.SHA256 != Digest(blob) {
			return Header{}, nil, nil, fmt.Errorf("%w: part %s", ErrDigestMismatch, part.Name)
		}
		blobs = append(blobs, blob)
	}

	return h, blobs[0], blobs[1:], nil
}

func describe(name string, blob []byte) Part {
	return Part{Name: name, Bytes: len(blob), SHA256: Digest(blob)}
}

// Digest is the SHA-256 of a part, in hex. The wire format depends on it, so it is
// exported rather than kept private.
func Digest(blob []byte) string {
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}
