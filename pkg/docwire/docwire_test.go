package docwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	source := []byte("\x00\x01sealed source bytes\xff")
	pages := [][]byte{[]byte("\x89PNG\r\n\x1a\npage one"), []byte("\x89PNG\r\n\x1a\npage two")}

	var buf bytes.Buffer
	err := Encode(&buf, Header{DocumentID: "abc123", KeyVersion: 3, DetectedType: "cbp_7501"}, source, pages)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	h, gotSource, gotPages, err := Decode(&buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if h.Schema != Schema {
		t.Fatalf("Schema = %q, want %q", h.Schema, Schema)
	}
	if h.DocumentID != "abc123" || h.KeyVersion != 3 || h.DetectedType != "cbp_7501" {
		t.Fatalf("header metadata lost: %+v", h)
	}
	if h.PageCount() != 2 || h.Source.Name != "source" || h.Pages[0].Name != "page-001" {
		t.Fatalf("parts not described as expected: %+v", h)
	}
	if !bytes.Equal(gotSource, source) {
		t.Fatalf("source round-trip = %q", gotSource)
	}
	if len(gotPages) != 2 || !bytes.Equal(gotPages[0], pages[0]) || !bytes.Equal(gotPages[1], pages[1]) {
		t.Fatalf("pages round-trip wrong")
	}
	if h.TotalBytes() != len(source)+len(pages[0])+len(pages[1]) {
		t.Fatalf("TotalBytes = %d", h.TotalBytes())
	}
}

func TestBytesTravelRaw(t *testing.T) {
	source := bytes.Repeat([]byte("\xde\xad\xbe\xef"), 64)

	var buf bytes.Buffer
	if err := Encode(&buf, Header{DocumentID: "x", KeyVersion: 1}, source, nil); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if !bytes.Contains(buf.Bytes(), source) {
		t.Fatal("the source does not appear verbatim in the container — base64 or escaping crept in")
	}
	// 8 bytes of framing, a header, and the source exactly.
	if buf.Len() <= len(source) {
		t.Fatal("container is smaller than its payload")
	}
}

func TestEmptySourceAndEmptyPageRefused(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, Header{}, nil, nil); err == nil {
		t.Fatal("Encode accepted an empty source")
	}
	if err := Encode(&buf, Header{}, []byte("x"), [][]byte{nil}); err == nil {
		t.Fatal("Encode accepted an empty page")
	}
}

func TestDecodeRejectsTamperedPart(t *testing.T) {
	source := []byte("sealed source")
	var buf bytes.Buffer
	if err := Encode(&buf, Header{DocumentID: "x", KeyVersion: 1}, source, nil); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	container := buf.Bytes()
	container[len(container)-1] ^= 0xff // last byte of the source

	if _, _, _, err := Decode(bytes.NewReader(container)); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("Decode of a tampered part = %v, want ErrDigestMismatch", err)
	}
}

func TestDecodeRejectsForeignAndTruncatedInput(t *testing.T) {
	valid := func() []byte {
		var buf bytes.Buffer
		if err := Encode(&buf, Header{DocumentID: "x", KeyVersion: 1}, []byte("sealed source"), nil); err != nil {
			t.Fatalf("Encode: %v", err)
		}
		return buf.Bytes()
	}()

	cases := map[string][]byte{
		"empty":         nil,
		"wrong magic":   []byte("XXXX\x00\x00\x00\x02{}"),
		"header only":   valid[:len(valid)-4],
		"no header":     []byte(Magic + "\x00\x00\x00\x10"),
		"zero length":   []byte(Magic + "\x00\x00\x00\x00"),
		"plain pdf":     []byte("%PDF-1.3 this is not a container"),
		"header claims": append([]byte(Magic), 0xff, 0xff, 0xff, 0xff),
	}
	for name, container := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := Decode(bytes.NewReader(container)); !errors.Is(err, ErrNotDocwire) {
				t.Fatalf("Decode(%s) = %v, want ErrNotDocwire", name, err)
			}
		})
	}
}

func TestDecodeRejectsUnknownSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, Header{DocumentID: "x", KeyVersion: 1}, []byte("sealed source"), nil); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	container := buf.Bytes()
	headerLen := int(binary.BigEndian.Uint32(container[4:8]))
	header := string(container[8 : 8+headerLen])
	// Same length on purpose: the point is to change the schema, not to shift the
	// part bytes and trip the digest check instead.
	patched := bytes.Replace(container, []byte(header), []byte(replaceAll(header, Schema, "sealed-document/9")), 1)

	if _, _, _, err := Decode(bytes.NewReader(patched)); !errors.Is(err, ErrNotDocwire) {
		t.Fatalf("Decode of an unknown schema = %v, want ErrNotDocwire", err)
	}
}

func TestDecodeRejectsAbsurdDeclaredLength(t *testing.T) {
	header := `{"schema":"` + Schema + `","document_id":"x","key_version":1,` +
		`"source":{"name":"source","bytes":2000000000,"sha256":""}}`
	container := append([]byte(Magic), 0, 0, 0, byte(len(header)))
	container = append(container, header...)

	if _, _, _, err := Decode(bytes.NewReader(container)); !errors.Is(err, ErrNotDocwire) {
		t.Fatalf("Decode of an absurd declared length = %v, want ErrNotDocwire", err)
	}
}

func replaceAll(s, old, new string) string {
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
