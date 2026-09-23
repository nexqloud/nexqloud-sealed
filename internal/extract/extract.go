// Package extract turns one document into the fields printed on it, inside the
// enclosure.
//
// The document is read by the model the sealed guest already runs. Two things make
// that a document read rather than a chat answer:
//
//   - the output is constrained to the caller's schema, so an unparseable answer is
//     not something to catch afterwards — the engine cannot produce one;
//   - the engine reports the probability of every token it wrote, so each field's
//     confidence is measured rather than self-reported.
//
// This package is deliberately pure: it builds the prompt, reads the answer back
// and measures it. The model call itself belongs to the caller, which keeps every
// rule here testable without a model.
package extract

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"nexqloud-sealed/internal/inference"
)

// ErrUnusableSchema means the caller's schema cannot describe an extraction.
var ErrUnusableSchema = errors.New("extract: schema has no properties")

// ErrNoPages means an image read was asked for with nothing to attach. A document that renders no
// pages cannot be read as pictures, and an empty picture set is not a read at all.
var ErrNoPages = errors.New("extract: no pages to attach")

// Request is one document read.
type Request struct {
	// SchemaID names the schema in the receipt, e.g. "cbp_7501".
	SchemaID string
	// Schema is the JSON schema the answer must satisfy. It is handed to the engine
	// as a constraint, which is why it is not repeated inside the prompt.
	Schema json.RawMessage
	// Document is the document's text, page breaks marked with a form feed.
	Document string
}

// Answer is what the model returned.
type Answer struct {
	Fields map[string]any `json:"fields"`
	// Confidence is the model's own opinion, when it gave one. The measured
	// confidence from logprobs replaces it, so this is kept for comparison only.
	Confidence map[string]float64 `json:"confidence"`
}

// BuildPrompt writes the instruction the model is given.
//
// The field names are listed even though the schema constrains the output: the
// constraint guarantees the shape, the list tells the model what to look for, and
// a list costs nothing if the engine turns out to be one that ignores grammars.
//
// A value that is not printed must come back as null, so the schema's own
// properties have to allow null. A schema that requires every field to be a string
// leaves the model no honest answer for a blank box — it can only invent one or
// break the grammar.
func BuildPrompt(schema json.RawMessage, document string) (string, error) {
	fields, err := schemaFields(schema)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	writeReadHeader(&b)
	writeFieldList(&b, fields, schemaFieldNotes(schema))
	b.WriteString("\n")
	b.WriteString("The document text follows. A form feed marks a page break.\n")
	b.WriteString("<<<DOCUMENT\n")
	b.WriteString(document)
	if !strings.HasSuffix(document, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("DOCUMENT>>>\n")
	return b.String(), nil
}

// PageImage describes one page picture attached to a read.
//
// The digest travels in the prompt on purpose: the receipt's prompt_hash covers the prompt string,
// and the pictures are not in it. Naming each page by its sha256 is what ties the receipt to the
// exact pictures that were read, rather than to a question that could have been asked of anything.
// PageImage is one picture attached to a read: a page, or — when a page had to be cut up to keep
// its small print readable — one horizontal strip of it.
type PageImage struct {
	Number   int
	SHA256   string
	MIMEType string
	Bytes    int
	// Band and Bands say where this image sits in a page that was cut up: strip 2 of 5. Bands <= 1
	// means the whole page is in this one image, which is the ordinary case.
	Band  int
	Bands int
}

// BuildImagePrompt is BuildPrompt for a document that has no text layer.
//
// A scan is a picture of a form. There is no text to quote, so the pages themselves go to the
// model — the same question, the same schema, the same measurement, asked of pictures. The prompt
// says so, and names every page it is attaching.
func BuildImagePrompt(schema json.RawMessage, pages []PageImage) (string, error) {
	fields, err := schemaFields(schema)
	if err != nil {
		return "", err
	}
	if len(pages) == 0 {
		return "", ErrNoPages
	}

	var b strings.Builder
	writeReadHeader(&b)
	b.WriteString("This document has no text layer. Its pages are attached to this request as images, in\n")
	b.WriteString("order, and they are the document: read what is printed on them, not a transcription of them.\n")
	banded := false
	for _, page := range pages {
		if page.Bands > 1 {
			banded = true
		}
	}
	if banded {
		b.WriteString("A page wider than the encoder's budget arrives as several horizontal strips, top to bottom,\n")
		b.WriteString("each overlapping the previous one by a little: read the strips of a page as one page, and\n")
		b.WriteString("take any value that appears in two strips once — the overlap is there so a line of print is\n")
		b.WriteString("never cut in half.\n")
	}
	b.WriteString("\n")
	writeFieldList(&b, fields, schemaFieldNotes(schema))
	b.WriteString("\n")
	b.WriteString("The attached pages are:\n")
	for _, page := range pages {
		mimeType := strings.TrimSpace(page.MIMEType)
		if mimeType == "" {
			mimeType = "image/png"
		}
		if page.Bands > 1 && page.Band > 0 {
			fmt.Fprintf(&b, "  - page %d, strip %d of %d: %s, %d bytes, sha256=%s\n",
				page.Number, page.Band, page.Bands, mimeType, page.Bytes, page.SHA256)
			continue
		}
		fmt.Fprintf(&b, "  - page %d: %s, %d bytes, sha256=%s\n", page.Number, mimeType, page.Bytes, page.SHA256)
	}
	return b.String(), nil
}

// writeReadHeader is the instruction every read shares, worded the same for text and pictures.
func writeReadHeader(b *strings.Builder) {
	b.WriteString("You read one customs document and return the fields printed on it.\n")
	b.WriteString("Use only what is printed on the page. Do not infer, normalise, reformat or complete a value.\n")
	b.WriteString("If a value is not printed, use null for it — never a guess and never a placeholder.\n")
	b.WriteString("\n")
	b.WriteString(`Answer with one JSON object and nothing else: {"fields": {"<field>": <value>, ...}}`)
	b.WriteString("\n\n")
}

// writeFieldList names the fields, with whatever the caller wrote about each of them.
func writeFieldList(b *strings.Builder, fields []string, notes map[string]schemaFieldNote) {
	b.WriteString("The fields are:\n")
	for _, field := range fields {
		note := notes[field]
		switch {
		case note.Description != "" && len(note.Enum) > 0:
			fmt.Fprintf(b, "  - %s: %s (one of: %s)\n", field, note.Description, quoted(note.Enum))
		case note.Description != "":
			fmt.Fprintf(b, "  - %s: %s\n", field, note.Description)
		case len(note.Enum) > 0:
			fmt.Fprintf(b, "  - %s (one of: %s)\n", field, quoted(note.Enum))
		default:
			fmt.Fprintf(b, "  - %s\n", field)
		}
	}
}

// schemaFields lists a schema's property names, sorted so the same schema always
// produces the same prompt.
func schemaFields(schema json.RawMessage) ([]string, error) {
	var parsed struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		return nil, fmt.Errorf("extract: schema is not json: %w", err)
	}
	if len(parsed.Properties) == 0 {
		return nil, ErrUnusableSchema
	}
	fields := make([]string, 0, len(parsed.Properties))
	for name := range parsed.Properties {
		fields = append(fields, name)
	}
	sort.Strings(fields)
	return fields, nil
}

// Fields exposes a schema's field names, so a caller can ask for a confidence for
// each of them.
func Fields(schema json.RawMessage) ([]string, error) { return schemaFields(schema) }

// schemaFieldNote is what the caller said about one field, in the words the model needs.
type schemaFieldNote struct {
	Description string
	Enum        []any
}

// schemaFieldNotes reads each property's description and, when the caller declared one, the
// closed set of values it may hold.
//
// Listing fields by name is not always enough. On a document read it usually is: a field called
// `duty_paid_usd` says what it holds, and the page supplies the rest. It is not enough when the
// answer is a *choice*: asked for `kind` with no list of kinds and a page that plainly reads
// COMMERCIAL INVOICE, the engine answered null and the read was thrown away. What the caller
// wrote about a field is the only place that list can come from, so it is carried into the
// prompt — the descriptions the callers wrote were never reaching the model.
func schemaFieldNotes(schema json.RawMessage) map[string]schemaFieldNote {
	var parsed struct {
		Properties map[string]struct {
			Description string `json:"description"`
			Enum        []any  `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		return nil
	}
	notes := make(map[string]schemaFieldNote, len(parsed.Properties))
	for name, property := range parsed.Properties {
		note := schemaFieldNote{
			Description: strings.TrimSpace(property.Description),
			Enum:        property.Enum,
		}
		if note.Description == "" && len(note.Enum) == 0 {
			continue
		}
		notes[name] = note
	}
	return notes
}

// quoted renders an allowed-value list the way the prompt should read it.
func quoted(values []any) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			parts = append(parts, strconv.Quote(text))
			continue
		}
		parts = append(parts, fmt.Sprintf("%v", value))
	}
	return strings.Join(parts, ", ")
}

// EnvelopeSchema is the schema handed to the engine as a constraint.
//
// The caller's schema describes the values it wants and how they must be formatted: a
// pattern here, a number there. Used directly as a grammar it does two harmful things —
// it coerces what the page actually prints ("USD 18,402.00" comes back as 18402, "none"
// as null) and, with every property optional, it lets the engine stop after the first
// field. Both were measured against a llama.cpp guest.
//
// What the engine is constrained to here is the *envelope*: the wrapper the prompt asks
// for and every field name in it, each value a plain string or null. So the answer cannot
// be prose, cannot be truncated mid-object and cannot lose a field, while the model still
// copies what the page says. The caller's own schema is enforced where it belongs — in
// the app, against the raw answer the receipt covers by digest.
func EnvelopeSchema(schema json.RawMessage) (json.RawMessage, error) {
	fields, err := schemaFields(schema)
	if err != nil {
		return nil, err
	}
	notes := schemaFieldNotes(schema)
	properties := make(map[string]any, len(fields))
	for _, field := range fields {
		value := map[string]any{"type": []string{"string", "null"}}
		// A caller's closed set of values is the one constraint that survives: it cannot
		// coerce what a page prints — which is exactly why patterns and number types are
		// dropped above — and it is what makes a *choice* (this document is one of these
		// kinds) closed rather than open-ended. null stays legal, so "no answer" is still an
		// answer a caller can see and route to review.
		if values := notes[field].Enum; len(values) > 0 {
			value["enum"] = append(append([]any{}, values...), nil)
		}
		properties[field] = value
	}
	return json.Marshal(map[string]any{
		"type": "object",
		"properties": map[string]any{
			"fields": map[string]any{
				"type":                 "object",
				"properties":           properties,
				"required":             fields,
				"additionalProperties": false,
			},
		},
		"required":             []string{"fields"},
		"additionalProperties": false,
	})
}

// Parse reads the model's answer.
//
// An answer wrapped in prose or a code fence is tolerated because a caller cannot
// control every engine's output, but a truncated or malformed object is refused:
// half an extraction presented as a whole one is worse than no extraction.
func Parse(content string) (Answer, error) {
	raw := trimToJSON(content)
	if raw == "" {
		return Answer{}, errors.New("extract: model returned no json")
	}

	var answer Answer
	if err := json.Unmarshal([]byte(raw), &answer); err != nil {
		return Answer{}, fmt.Errorf("extract: model answer is not json: %w", err)
	}

	if answer.Fields == nil {
		// No wrapper: treat the object itself as the fields. This is what an engine
		// that ignored the schema returns, and reading it beats discarding it.
		var bare map[string]any
		if err := json.Unmarshal([]byte(raw), &bare); err != nil {
			return Answer{}, fmt.Errorf("extract: model answer is not json: %w", err)
		}
		if len(bare) == 0 {
			return Answer{}, errors.New("extract: model returned an empty object")
		}
		return Answer{Fields: bare}, nil
	}
	return answer, nil
}

// trimToJSON cuts an answer down to the JSON object inside it.
func trimToJSON(content string) string {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```") {
		if end := strings.LastIndex(content, "```"); end > 0 {
			content = strings.TrimSpace(content[3:end])
			content = strings.TrimPrefix(content, "json")
			content = strings.TrimSpace(content)
		}
	}
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start < 0 || end <= start {
		return ""
	}
	return content[start : end+1]
}

// Confidence measures how sure the engine was of each field's value, from the
// probability it reported for each token it wrote.
//
// A value is only as trustworthy as the weakest token in it, so a field's
// confidence is the least likely token inside that field's span. The span runs from
// the end of the field's key to the start of the next key. Tokens that are nothing
// but punctuation are ignored, because a brace or a comma the engine was unsure of
// says nothing about whether it read the value correctly — and a token such as `}}`
// straddles a value and the object around it, so counting it would charge the field
// for the wrapper.
//
// It returns nil when the engine reported no token probabilities. Absent means not
// measured, and a caller must treat it that way rather than as a confidence of zero
// or one.
func Confidence(content string, tokens []inference.TokenLogprob, fields []string) map[string]float64 {
	if len(tokens) == 0 || len(fields) == 0 {
		return nil
	}

	// Recover where each token sits in the answer. Concatenating the tokens
	// reproduces the text the engine emitted, so offsets taken from the
	// concatenation are the offsets of the raw answer by construction.
	type tokenSpan struct {
		start, end int
		logprob    float64
	}
	var text strings.Builder
	spans := make([]tokenSpan, 0, len(tokens))
	for _, token := range tokens {
		start := text.Len()
		text.WriteString(token.Token)
		spans = append(spans, tokenSpan{start: start, end: text.Len(), logprob: token.Logprob})
	}
	haystack := text.String()

	lastBrace := strings.LastIndex(haystack, "}")
	out := make(map[string]float64, len(fields))

	for _, field := range fields {
		key := `"` + field + `"`
		keyAt := strings.Index(haystack, key)
		if keyAt < 0 {
			continue // not in the answer: no value, so nothing to be confident about
		}
		start := keyAt + len(key)

		end := len(haystack)
		if lastBrace > start && lastBrace < end {
			end = lastBrace
		}
		for _, other := range fields {
			if other == field {
				continue
			}
			if next := strings.Index(haystack[start:], `"`+other+`"`); next >= 0 {
				if abs := start + next; abs < end {
					end = abs
				}
			}
		}
		if end <= start {
			continue
		}

		weakest, seen, structuralWeakest, structuralSeen := 0.0, false, 0.0, false
		for _, span := range spans {
			if span.end <= start || span.start >= end {
				continue
			}
			if isStructuralText(haystack[span.start:span.end]) {
				if !structuralSeen || span.logprob < structuralWeakest {
					structuralWeakest, structuralSeen = span.logprob, true
				}
				continue
			}
			if !seen || span.logprob < weakest {
				weakest, seen = span.logprob, true
			}
		}
		if !seen {
			// A value with no content of its own — an empty string, or null written as
			// punctuation — is measured on whatever the engine did write.
			if !structuralSeen {
				continue
			}
			weakest, seen = structuralWeakest, true
		}
		out[field] = round4(clamp01(math.Exp(weakest)))
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

// isStructuralText reports whether a token is nothing but the punctuation holding
// the answer together. A value's confidence is about the value: whether the engine
// was sure of a brace or a comma says nothing about whether it read the document,
// and a token such as `}}` straddles a value and the object around it, so counting
// it would charge the field for the wrapper.
func isStructuralText(token string) bool {
	if token == "" {
		return true
	}
	for _, r := range token {
		switch r {
		case '{', '}', '[', ']', ',', ':', '"', ' ', '	', '\n', '\r':
		default:
			return false
		}
	}
	return true
}

// round4 keeps a confidence stable across runs and compact in a receipt.
func round4(v float64) float64 { return math.Round(v*10000) / 10000 }
