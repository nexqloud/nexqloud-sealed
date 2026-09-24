package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"nexqloud-sealed/internal/documents"
	"nexqloud-sealed/internal/redact"
	"nexqloud-sealed/pkg/docwire"
)

// Where a value is printed is worked out once, when the document is read, and kept in the container
// the application stores. Finding it again at review time is the same work a second time, in front of
// a person, on an engine that reads one page at a time — and the pages that were read are exactly the
// pages a review shows. So the locating happens at extraction and travels as a part of its own.
//
// The application never learns a coordinate: what it keeps is sealed bytes under the document's own
// key, and only this side ever opens them.

// regionsVersion is the shape of the payload inside the regions part. A reader refuses a version it
// does not know rather than guessing what the numbers mean.
const regionsVersion = 1

// regionPayload is the sealed body of the regions part: where each value was located, in the page's
// own points measured from its top left — the space poppler reports words in, and the space a page
// render is drawn in — plus what found them.
type regionPayload struct {
	Version     int                     `json:"version"`
	SchemaID    string                  `json:"schema_id,omitempty"`
	LocatedFrom string                  `json:"located_from"`
	Fields      map[string]regionOnPage `json:"fields"`
}

// regionOnPage is one located value: which page, and the region it sits in.
type regionOnPage struct {
	Page   int     `json:"page"`
	Left   float64 `json:"left"`
	Top    float64 `json:"top"`
	Right  float64 `json:"right"`
	Bottom float64 `json:"bottom"`
}

// regionsPart is where an extraction located each value it read, on its way to the caller: the part
// as it goes into the container's own header, and the sealed bytes themselves.
//
// The part description is written on this side, word for word. A caller copies it into the header
// beside the bytes rather than making up a name, a size or a digest for bytes it cannot read — the
// two sides then agree on the part's shape without the caller having to know it.
type regionsPart struct {
	Part        docwire.Part `json:"part"`
	BytesBase64 string       `json:"bytes_base64"`
	// LocatedFrom says what the regions were found in: the document's own text layer (`text`, which
	// is exact) or its pages as pictures (`page_images`, where the engine that read them placed them).
	LocatedFrom string `json:"located_from,omitempty"`
	// Fields is how many values were placed, Asked how many were looked for. A review is told what
	// was located rather than left to infer it from the page it is shown.
	Fields int `json:"fields"`
	Asked  int `json:"asked"`
}

// splitter is how this deployment reads a page's own words and where they are printed. Empty means
// the guest's converter, which is what a deployment runs.
func (s *server) splitter() redact.Splitter {
	if s.words != nil {
		return s.words
	}
	return redact.Exec{}
}

// regionsForTheReview works out where the values of a read are printed and seals them.
//
// It is called from the extraction door, where the pages have just been read and the images the
// engine saw are still in hand — for a picture read, the only place they exist.
//
// Everything here is optional by design: a read that cannot be located is still a read. The caller
// gets its fields and its receipt either way, and a review locates for itself exactly as it did
// before, so nothing depends on this succeeding.
func (s *server) regionsForTheReview(
	ctx context.Context,
	dek []byte,
	keyVersion int,
	source []byte,
	pages [][]byte,
	fields map[string]any,
	schemaID, model, tenant, nonce string,
) *regionsPart {
	values := valuesOnThePage(fields)
	if len(values) == 0 {
		return nil
	}

	dims, err := s.splitter().Pages(ctx, source)
	if err != nil {
		log.Printf("[sealed] read: the page's own words could not be read (%v), so nothing was located for a review", err)
		return nil
	}
	if len(pages) != 0 && len(pages) != len(dims) {
		// The renders and the document disagree about how many pages it has; a region found on one
		// is not a region on the other.
		log.Printf("[sealed] read: %d page render(s) against %d page(s) of the document, so nothing was located", len(pages), len(dims))
		return nil
	}

	found, missing := s.locateForReview(ctx, dims, pages, values, func(ctx context.Context, ask map[string]any) map[string]redact.Box {
		return s.boxesFromModel(ctx, ask, pages, dims, model, tenant, nonce)
	})
	if len(found) == 0 {
		log.Printf("[sealed] read: none of the %d value(s) could be located on the page; a review will locate for itself", len(values))
		return nil
	}

	locatedFrom := readFromText
	if redact.Textless(dims) {
		locatedFrom = readFromPageImages
	}
	sealed, err := sealRegions(dek, keyVersion, schemaID, locatedFrom, found)
	if err != nil {
		log.Printf("[sealed] read: the located regions could not be sealed (%v); a review will locate for itself", err)
		return nil
	}
	if len(missing) == 0 {
		log.Printf("[sealed] read: located all %d value(s) on %d page(s) from %s, for the review to reuse", len(found), len(dims), locatedFrom)
	} else {
		log.Printf("[sealed] read: located %d of %d value(s) from %s (no region for %s); a review reuses what was found",
			len(found), len(values), locatedFrom, joinFields(missing))
	}
	return &regionsPart{
		Part:        docwire.Part{Name: docwire.RegionsName, Bytes: len(sealed), SHA256: docwire.Digest(sealed)},
		BytesBase64: base64.StdEncoding.EncodeToString(sealed),
		LocatedFrom: locatedFrom,
		Fields:      len(found),
		Asked:       len(values),
	}
}

// locateForReview finds each value on the pages of a document this side is holding: from the pages'
// own words where they have any, and from the engine that read them where they have none.
//
// The second half is why this is one function and not two. A scanned page has no words, so the only
// thing that can say where a value is printed on it is the engine that was shown it — and the engine
// is asked only about the values the words could not place, and only when every page of the document
// is wordless. A digital page's words are exact and free; a model call on every read is neither.
//
// It returns every region it could place and the names it could not, so the caller can say what is
// missing rather than quietly showing less than it was asked for.
func (s *server) locateForReview(
	ctx context.Context,
	dims []redact.Page,
	pages [][]byte,
	values map[string]any,
	askModel func(context.Context, map[string]any) map[string]redact.Box,
) (map[string]redact.Box, map[string]struct{}) {
	found, missing := redact.Locate(dims, values)
	if len(missing) == 0 || !redact.Textless(dims) || askModel == nil {
		return found, missing
	}
	ask := make(map[string]any, len(missing))
	for field := range missing {
		ask[field] = values[field]
	}
	for field, box := range askModel(ctx, ask) {
		found[field] = box
		delete(missing, field)
	}
	return found, missing
}

// valuesOnThePage names every value a read produced that a page could be searched for, the way the
// screen that asks for a review names it: a value inside a list of rows is `<key>.<row>.<leaf>`, the
// rows counted from 1. That is the same name the tariff application gives that same value when it
// asks for a redacted page, which is what lets the two halves meet without either of them restating
// the other's vocabulary. A name nothing asks for costs nothing — it is simply never used.
//
// No rule about tariffs is here. A list of rows is how a form's line grid is spelled in the schema,
// and this side only needs to know which of the values read are worth looking for.
func valuesOnThePage(fields map[string]any) map[string]any {
	out := map[string]any{}
	for name, value := range fields {
		if rows, ok := value.([]any); ok {
			// A list of rows is the one shape the schema asks for, and the only one whose row numbers
			// this side can know: the caller numbers them from one, in the order the answer carries.
			for index, row := range rows {
				object, ok := row.(map[string]any)
				if !ok {
					continue
				}
				for leaf, leafValue := range object {
					if !worthLocating(leafValue) {
						continue
					}
					out[fmt.Sprintf("%s.%d.%s", name, index+1, leaf)] = leafValue
				}
			}
			continue
		}
		// Any other shape — a list of values, a grid keyed by row — is left to the review's own pass.
		// The names would be the caller's, numbering rows by an order this side cannot reproduce (a
		// map has none), and a region stored under the wrong row number would show a reviewer the wrong
		// part of the page. A miss costs only the second locating pass; a wrong region costs the review.
		if worthLocating(value) {
			out[name] = value
		}
	}
	return out
}

// worthLocating is whether a stored value is one a page could be searched for at all.
//
// A missing value has nothing to find, and an empty string is not printed. A flag is a value: the
// application keeps one for a checkbox and asks for the region of the field, and this is the same
// set the review would have searched for itself, so it is looked for here too.
func worthLocating(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool, float64, int, int64:
		return true
	case string:
		return typed != ""
	case []any, map[string]any:
		return false
	}
	return false
}

// sealRegions seals where each value was located under the document's own key.
func sealRegions(dek []byte, keyVersion int, schemaID, locatedFrom string, found map[string]redact.Box) ([]byte, error) {
	payload := regionPayload{
		Version:     regionsVersion,
		SchemaID:    schemaID,
		LocatedFrom: locatedFrom,
		Fields:      make(map[string]regionOnPage, len(found)),
	}
	for field, box := range found {
		payload.Fields[field] = regionOnPage{
			Page:   box.Page,
			Left:   box.Left,
			Top:    box.Top,
			Right:  box.Right,
			Bottom: box.Bottom,
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode the located regions: %w", err)
	}
	return documents.Seal(dek, keyVersion, documents.KindRegions, encoded)
}

// openRegions opens the regions part of a container the application kept, and reports nothing at all
// when it cannot.
//
// That is the honest answer rather than a failure: a container written before this change has no
// regions in it, a container that changed on the way here fails its tag, and an older payload is a
// shape this reader does not know. The caller's next move is the same in every case — locate for
// itself — so this says nothing to the wire and only writes down why it came back empty.
func openRegions(dek []byte, keyVersion int, sealed []byte) map[string]redact.Box {
	if len(sealed) == 0 {
		return nil
	}
	kind, plaintext, err := documents.Open(dek, sealed, keyVersion)
	if err != nil {
		log.Printf("document read-key: the stored regions cannot be opened (%v); locating them again", err)
		return nil
	}
	if kind != documents.KindRegions {
		log.Printf("document read-key: the regions part carries a %s", kind)
		return nil
	}

	var payload regionPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		log.Printf("document read-key: the stored regions are not readable (%v); locating them again", err)
		return nil
	}
	if payload.Version != regionsVersion {
		log.Printf("document read-key: the stored regions are version %d, which this deployment does not read", payload.Version)
		return nil
	}
	if len(payload.Fields) == 0 {
		return nil
	}

	out := make(map[string]redact.Box, len(payload.Fields))
	for field, region := range payload.Fields {
		box := redact.Box{Page: region.Page, Left: region.Left, Top: region.Top, Right: region.Right, Bottom: region.Bottom}
		// A region that is not a region is worse than none: it would be painted as something a
		// reviewer should look at.
		if box.Page < 1 || box.Right <= box.Left || box.Bottom <= box.Top {
			log.Printf("document read-key: the stored region for %s is not a region", field)
			continue
		}
		out[field] = box
	}
	if len(out) == 0 {
		return nil
	}
	log.Printf("document read-key: %d value(s) of this document were located when it was read, from %s",
		len(out), payload.LocatedFrom)
	return out
}
