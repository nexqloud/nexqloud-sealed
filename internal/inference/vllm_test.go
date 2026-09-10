package inference

import (
	"io"
	"strings"
	"testing"
)

func TestReadStreamKeepsTokensAfterUnexpectedEOF(t *testing.T) {
	body := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n"
	out, err := readStream(&errAfter{Reader: strings.NewReader(body), err: io.ErrUnexpectedEOF}, "m", nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Content != "Hello" {
		t.Fatalf("got %q", out.Content)
	}
}

func TestReadStreamFallsBackToJSONBody(t *testing.T) {
	raw := `{"choices":[{"message":{"content":"hi there"}}]}`
	out, err := readStream(strings.NewReader(raw), "m", nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Content != "hi there" {
		t.Fatalf("got %q", out.Content)
	}
}

type errAfter struct {
	io.Reader
	err error
}

func (r *errAfter) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		return n, r.err
	}
	return n, err
}
