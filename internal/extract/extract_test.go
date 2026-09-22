package extract

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"nexqloud-sealed/internal/inference"
)

const eeiSchema = `{
  "type": "object",
  "properties": {
    "export_ref":  {"type": ["string", "null"]},
    "export_date": {"type": ["string", "null"]},
    "hts_10":      {"type": ["string", "null"]},
    "part_number": {"type": ["string", "null"]},
    "qty":         {"type": ["number", "null"]},
    "uom":         {"type": ["string", "null"]}
  },
  "required": ["export_ref", "hts_10"]
}`

const documentText = "AES EEI EXPORT PROOF\nExport reference EEI 2025-1130\nHTS 10 8207301500\nExported quantity 1200 PCS\n"

func TestBuildPromptListsTheFieldsAndTheDocument(t *testing.T) {
	prompt, err := BuildPrompt(json.RawMessage(eeiSchema), documentText)
	if err != nil {
		t.Fatalf("BuildPrompt: %v", err)
	}

	if !strings.Contains(prompt, documentText) {
		t.Fatal("the document is not in the prompt")
	}
	if !strings.Contains(prompt, "<<<DOCUMENT") || !strings.Contains(prompt, "DOCUMENT>>>") {
		t.Fatal("the document is not delimited")
	}
	if !strings.Contains(prompt, "form feed marks a page break") {
		t.Fatal("the prompt does not explain the page break")
	}
	for _, field := range []string{"export_ref", "export_date", "hts_10", "part_number", "qty", "uom"} {
		if !strings.Contains(prompt, "- "+field+"\n") {
			t.Fatalf("field %s is missing from the prompt", field)
		}
	}
	if !strings.Contains(prompt, "use null for it") {
		t.Fatal("the prompt does not say what to do with a value that is not printed")
	}
	// The schema is a constraint handed to the engine, not text repeated in the prompt.
	if strings.Contains(prompt, `"type": ["string", "null"]`) {
		t.Fatal("the schema was embedded in the prompt")
	}
}

func TestBuildPromptIsStableForTheSameSchema(t *testing.T) {
	first, err := BuildPrompt(json.RawMessage(eeiSchema), documentText)
	if err != nil {
		t.Fatalf("BuildPrompt: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := BuildPrompt(json.RawMessage(eeiSchema), documentText)
		if err != nil {
			t.Fatalf("BuildPrompt: %v", err)
		}
		if again != first {
			t.Fatal("the same schema produced a different prompt; the field order is not stable")
		}
	}
}

func TestBuildPromptRefusesAnUnusableSchema(t *testing.T) {
	cases := map[string]string{
		"no properties": `{"type":"object"}`,
		"empty":         `{"type":"object","properties":{}}`,
		"not json":      `{nope`,
		"empty string":  ``,
	}
	for name, schema := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildPrompt(json.RawMessage(schema), documentText); err == nil {
				t.Fatal("BuildPrompt accepted a schema that cannot describe an extraction")
			}
		})
	}
}

func TestFieldsReportsTheSchemaFieldNames(t *testing.T) {
	fields, err := Fields(json.RawMessage(eeiSchema))
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	want := []string{"export_date", "export_ref", "hts_10", "part_number", "qty", "uom"}
	if len(fields) != len(want) {
		t.Fatalf("got %v, want %v", fields, want)
	}
	for i := range want {
		if fields[i] != want[i] {
			t.Fatalf("fields = %v, want sorted %v", fields, want)
		}
	}
}

func TestParseReadsTheWrapper(t *testing.T) {
	answer, err := Parse(`{"fields":{"export_ref":"EEI 2025-1130","qty":1200},"confidence":{"qty":0.4}}`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if answer.Fields["export_ref"] != "EEI 2025-1130" {
		t.Fatalf("fields = %v", answer.Fields)
	}
	if answer.Fields["qty"] != float64(1200) {
		t.Fatalf("qty = %v", answer.Fields["qty"])
	}
	if answer.Confidence["qty"] != 0.4 {
		t.Fatalf("confidence = %v", answer.Confidence)
	}
}

func TestParseToleratesProseAndFences(t *testing.T) {
	for name, content := range map[string]string{
		"fenced":     "```json\n{\"fields\":{\"qty\":1200}}\n```",
		"prose":      "Here is the record:\n{\"fields\":{\"qty\":1200}}\nThat is all.",
		"bare":       `{"qty":1200}`,
		"whitespace": "\n\n  {\"fields\":{\"qty\":1200}}  \n",
	} {
		t.Run(name, func(t *testing.T) {
			answer, err := Parse(content)
			if err != nil {
				t.Fatalf("Parse(%s): %v", name, err)
			}
			if answer.Fields["qty"] != float64(1200) {
				t.Fatalf("fields = %v", answer.Fields)
			}
		})
	}
}

func TestParseRefusesATruncatedOrEmptyAnswer(t *testing.T) {
	cases := map[string]string{
		"empty":      "",
		"prose only": "I could not read this document.",
		"truncated":  `{"fields":{"qty":120`,
		"empty obj":  `{}`,
		"array":      `[1,2,3]`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(content); err == nil {
				t.Fatalf("Parse(%q) succeeded", content)
			}
		})
	}
}

// tokenStream builds a token list from pieces whose concatenation is the answer
// text, exactly as an engine reports them.
func tokenStream(pieces ...struct {
	text    string
	logprob float64
}) []inference.TokenLogprob {
	out := make([]inference.TokenLogprob, 0, len(pieces))
	for _, piece := range pieces {
		out = append(out, inference.TokenLogprob{Token: piece.text, Logprob: piece.logprob})
	}
	return out
}

func span(text string, logprob float64) struct {
	text    string
	logprob float64
} {
	return struct {
		text    string
		logprob float64
	}{text, logprob}
}

func TestConfidenceComesFromTheWeakestTokenInEachField(t *testing.T) {
	tokens := tokenStream(
		span(`{"fields":{`, -0.01),
		span(`"hts_10"`, -0.01),
		span(`:"`, -0.01),
		span(`8207301500`, -2.0), // the model was unsure of the code
		span(`",`, -0.01),
		span(`"qty"`, -0.01),
		span(`:1200`, -0.05),
		span(`}}`, -0.01),
	)
	answer := `{"fields":{"hts_10":"8207301500","qty":1200}}`
	if got := concat(tokens); got != answer {
		t.Fatalf("token stream does not reproduce the answer: %q", got)
	}

	conf := Confidence(answer, tokens, []string{"hts_10", "qty"})
	if conf == nil {
		t.Fatal("Confidence returned nothing for a measured answer")
	}
	if want := 0.1353; math.Abs(conf["hts_10"]-want) > 0.0002 {
		t.Fatalf("hts_10 confidence = %v, want ~%v from its weakest token", conf["hts_10"], want)
	}
	if want := 0.9512; math.Abs(conf["qty"]-want) > 0.0002 {
		t.Fatalf("qty confidence = %v, want ~%v", conf["qty"], want)
	}
	if conf["qty"] <= conf["hts_10"] {
		t.Fatal("a field the model was sure of scored no better than one it was unsure of")
	}
}

func TestConfidenceSkipsFieldsAbsentFromTheAnswer(t *testing.T) {
	tokens := tokenStream(span(`{"fields":{"qty":1200}}`, -0.05))
	conf := Confidence(`{"fields":{"qty":1200}}`, tokens, []string{"qty", "uom"})
	if _, ok := conf["uom"]; ok {
		t.Fatal("a field the model never wrote got a confidence")
	}
	if _, ok := conf["qty"]; !ok {
		t.Fatal("the field the model wrote got no confidence")
	}
}

func TestConfidenceIsNilWhenNothingWasMeasured(t *testing.T) {
	answer := `{"fields":{"qty":1200}}`
	if got := Confidence(answer, nil, []string{"qty"}); got != nil {
		t.Fatalf("Confidence without tokens = %v, want nil (not measured)", got)
	}
	if got := Confidence(answer, tokenStream(span(answer, -0.01)), nil); got != nil {
		t.Fatalf("Confidence without fields = %v, want nil", got)
	}
}

func TestConfidenceStaysInRange(t *testing.T) {
	answer := `{"fields":{"a":"x"}}`
	// A probability of 1 is the best case; a logprob above 0 is impossible but must
	// not produce a confidence above 1 if an engine ever reports one.
	tokens := tokenStream(span(`{"fields":{`, 0), span(`"a"`, 0), span(`:"x"`, 0.5), span(`}}`, 0))
	conf := Confidence(answer, tokens, []string{"a"})
	if conf["a"] < 0 || conf["a"] > 1 {
		t.Fatalf("confidence out of range: %v", conf["a"])
	}
	if conf["a"] != 1 {
		t.Fatalf("confidence = %v, want it clamped to 1", conf["a"])
	}
}

func TestConfidenceExcludesTheClosingBrace(t *testing.T) {
	answer := `{"fields":{"a":"x"}}`
	// The final token is very unlikely, but it is punctuation closing the object, not
	// part of the value.
	tokens := tokenStream(span(`{"fields":{`, -0.01), span(`"a"`, -0.01), span(`:"x"`, -0.01), span(`}}`, -8.0))
	conf := Confidence(answer, tokens, []string{"a"})
	if conf["a"] < 0.9 {
		t.Fatalf("confidence = %v; the closing brace was counted against the value", conf["a"])
	}
}

func TestConfidenceHandlesTheLastFieldWithoutAComma(t *testing.T) {
	answer := `{"fields":{"a":"x","b":"y"}}`
	tokens := tokenStream(
		span(`{"fields":{`, -0.01),
		span(`"a"`, -0.01), span(`:"x"`, -3.0), span(`",`, -0.01),
		span(`"b"`, -0.01), span(`:"y"`, -0.01),
		span(`}}`, -0.01),
	)
	conf := Confidence(answer, tokens, []string{"a", "b"})
	if math.Abs(conf["a"]-0.0498) > 0.0005 {
		t.Fatalf("a = %v, want ~0.0498", conf["a"])
	}
	if math.Abs(conf["b"]-0.9900) > 0.0005 {
		t.Fatalf("b = %v, want ~0.99", conf["b"])
	}
}

func TestTrimToJSON(t *testing.T) {
	cases := map[string]string{
		`{"a":1}`:                 `{"a":1}`,
		"pre {\"a\":1} post":      `{"a":1}`,
		"```json\n{\"a\":1}\n```": `{"a":1}`,
		"no json here":            ``,
		"":                        ``,
	}
	for input, want := range cases {
		if got := trimToJSON(input); got != want {
			t.Fatalf("trimToJSON(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEnvelopeSchemaConstrainsTheShapeNotTheValues(t *testing.T) {
	// A caller's pattern or number type must not reach the engine as a grammar: measured
	// against a llama.cpp guest, that coerced "USD 18,402.00" to 18402 and "none" to null.
	schema := json.RawMessage(`{"type":"object","properties":{` +
		`"hts_10":{"type":["string","null"],"pattern":"^\\d{10}$"},` +
		`"duty_paid_usd":{"type":["number","null"]}}}`)

	got, err := EnvelopeSchema(schema)
	if err != nil {
		t.Fatalf("EnvelopeSchema: %v", err)
	}

	var envelope struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Required             []string `json:"required"`
			AdditionalProperties bool     `json:"additionalProperties"`
			Properties           map[string]struct {
				Type []string `json:"type"`
			} `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(got, &envelope); err != nil {
		t.Fatalf("envelope is not json: %v", err)
	}

	if len(envelope.Required) != 1 || envelope.Required[0] != "fields" {
		t.Fatalf("envelope required = %v, want [fields]", envelope.Required)
	}
	fields, ok := envelope.Properties["fields"]
	if !ok {
		t.Fatalf("envelope has no fields object: %s", got)
	}
	if strings.Join(fields.Required, ",") != "duty_paid_usd,hts_10" {
		t.Fatalf("fields required = %v, want both fields so none can be dropped", fields.Required)
	}
	if fields.AdditionalProperties {
		t.Fatal("extra fields must not be allowed")
	}
	for name, property := range fields.Properties {
		if strings.Join(property.Type, "|") != "string|null" {
			t.Fatalf("%s type = %v, want string|null so the page's own text survives", name, property.Type)
		}
	}
	if body := string(got); strings.Contains(body, "pattern") || strings.Contains(body, "number") {
		t.Fatalf("caller formatting leaked into the grammar: %s", body)
	}
}

func TestEnvelopeSchemaRefusesAnUnusableSchema(t *testing.T) {
	_, err := EnvelopeSchema(json.RawMessage(`{"type":"object"}`))
	if !errors.Is(err, ErrUnusableSchema) {
		t.Fatalf("err = %v, want ErrUnusableSchema", err)
	}
}

func TestUnusableSchemaErrorIsIdentifiable(t *testing.T) {
	_, err := BuildPrompt(json.RawMessage(`{"type":"object"}`), documentText)
	if !errors.Is(err, ErrUnusableSchema) {
		t.Fatalf("err = %v, want ErrUnusableSchema", err)
	}
}

func concat(tokens []inference.TokenLogprob) string {
	var b strings.Builder
	for _, token := range tokens {
		b.WriteString(token.Token)
	}
	return b.String()
}
