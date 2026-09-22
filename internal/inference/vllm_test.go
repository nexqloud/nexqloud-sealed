package inference

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCompleteSendsConstraintsInTheEngineDialect(t *testing.T) {
	const schema = `{"type":"object","properties":{"hts_10":{"type":"string"}}}`

	cases := []struct {
		name       string
		dialect    Dialect
		schemaKey  string
		grammarKey string
	}{
		{name: "llama.cpp", dialect: DialectLlamaCpp, schemaKey: "json_schema", grammarKey: "grammar"},
		{name: "vllm", dialect: DialectVLLM, schemaKey: "guided_json", grammarKey: "guided_grammar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(body, &got); err != nil {
					t.Errorf("request body is not json: %v", err)
				}
				w.Write([]byte(`{"choices":[{"message":{"content":"{}"}}]}`))
			}))
			defer srv.Close()

			client := NewVLLM(srv.URL)
			client.Dialect = tc.dialect
			if _, err := client.Complete(Request{
				Model:       "m",
				Messages:    []Message{{Role: "user", Content: "hi"}},
				JSONSchema:  schema,
				Grammar:     `root ::= "x"`,
				Logprobs:    true,
				TopLogprobs: 3,
			}); err != nil {
				t.Fatalf("Complete: %v", err)
			}

			if _, ok := got[tc.schemaKey]; !ok {
				t.Fatalf("schema sent as %q, want it under %q", keys(got), tc.schemaKey)
			}
			if _, ok := got[tc.grammarKey]; !ok {
				t.Fatalf("grammar sent as %q, want it under %q", keys(got), tc.grammarKey)
			}
			if got["logprobs"] != true || got["top_logprobs"] != float64(3) {
				t.Fatalf("logprobs request missing: %v", got)
			}
		})
	}
}

func TestCompleteRejectsAnInvalidSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the request should never have been sent")
	}))
	defer srv.Close()

	client := NewVLLM(srv.URL)
	if _, err := client.Complete(Request{JSONSchema: "{not json"}); err == nil {
		t.Fatal("Complete accepted json_schema that is not valid json")
	}
}

func TestParseCompletionJSONReadsLogprobs(t *testing.T) {
	raw := []byte(`{"model":"m","choices":[{"message":{"content":"{\"fields\":{}}"},` +
		`"logprobs":{"content":[{"token":"{","logprob":-0.0102},{"token":"\"hts","logprob":-2.5}]}}]}`)

	resp, err := parseCompletionJSON(raw, "fallback")
	if err != nil {
		t.Fatalf("parseCompletionJSON: %v", err)
	}
	if len(resp.TokenLogprobs) != 2 {
		t.Fatalf("got %d token logprobs, want 2", len(resp.TokenLogprobs))
	}
	if resp.TokenLogprobs[0].Token != "{" || resp.TokenLogprobs[0].Logprob != -0.0102 {
		t.Fatalf("first token = %+v", resp.TokenLogprobs[0])
	}
	if resp.TokenLogprobs[1].Token != `"hts` || resp.TokenLogprobs[1].Logprob != -2.5 {
		t.Fatalf("second token = %+v", resp.TokenLogprobs[1])
	}
}

func TestNoLogprobsIsNotMeasuredAsZero(t *testing.T) {
	resp, err := parseCompletionJSON([]byte(`{"choices":[{"message":{"content":"hi"}}]}`), "m")
	if err != nil {
		t.Fatalf("parseCompletionJSON: %v", err)
	}
	if resp.TokenLogprobs != nil {
		t.Fatalf("a response with no logprobs produced %d tokens; empty must mean not measured", len(resp.TokenLogprobs))
	}
}

func TestMockNeverInventsAFieldValue(t *testing.T) {
	out, err := NewMock().Complete(Request{JSONSchema: `{"type":"object"}`})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	var parsed struct {
		Fields map[string]any `json:"fields"`
	}
	if err := json.Unmarshal([]byte(out.Content), &parsed); err != nil {
		t.Fatalf("mock answer under a schema is not json: %q", out.Content)
	}
	if len(parsed.Fields) != 0 {
		t.Fatalf("mock invented fields: %v", parsed.Fields)
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

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
