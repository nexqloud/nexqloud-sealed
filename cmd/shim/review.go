package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	"nexqloud-sealed/internal/documents"
	"nexqloud-sealed/internal/readkey"
	"nexqloud-sealed/internal/redact"
	"nexqloud-sealed/pkg/docwire"
)

// sealForRecipient seals every part that is going to a recipient under the session key.
//
// It exists because of a bug: the pages were sealed and the pieces were not, so a redacted document
// travelled with legible regions of it in the clear beside the pages. Nothing leaves the enclave
// unsealed, and this is the one door out, so a new kind of part cannot miss it by being appended
// somewhere else.
func sealForRecipient(sessionKey []byte, pages [][]byte, pieces []docwire.Named) ([][]byte, []docwire.Named, error) {
	sealedPages := make([][]byte, 0, len(pages))
	for index, page := range pages {
		blob, err := readkey.SealPage(sessionKey, page)
		if err != nil {
			return nil, nil, fmt.Errorf("seal page %d: %w", index+1, err)
		}
		sealedPages = append(sealedPages, blob)
	}
	sealedPieces := make([]docwire.Named, 0, len(pieces))
	for _, piece := range pieces {
		blob, err := readkey.SealPage(sessionKey, piece.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("seal piece %q: %w", piece.Name, err)
		}
		sealedPieces = append(sealedPieces, docwire.Named{Name: piece.Name, Bytes: blob})
	}
	return sealedPages, sealedPieces, nil
}

// pageModeRedacted is the only page a reviewer is ever handed: the regions under review, with a black
// rectangle over everything else. Nothing in this package returns a whole page, and there is no mode
// that asks for one.
const pageModeRedacted = "redacted"

// redactForReview paints every part of every page that is not under review out of that page's render,
// and cuts one piece per value so a reviewer can look at a single field closely.
//
// The fields are named by the application, which is the side that knows what the claim is worked out
// from. This side only finds them in the document it holds and removes everything else, so no rule
// about tariffs lives here.
//
// Two failures are normal and are handed back as they are, because the caller has to be able to say
// why nothing was shown rather than showing something unredacted: a document with no text to find a
// value in (a scan), and a document where not one value under review could be located.
func (s *server) redactForReview(ctx context.Context, dek []byte, keyVersion int, sealedSource []byte, pages [][]byte, fields map[string]any, locateScan func(context.Context, map[string]any, [][]byte, []redact.Page) map[string]redact.Box) (out [][]byte, pieces []docwire.Named, located int, err error) {
	kind, source, err := documents.Open(dek, sealedSource, keyVersion)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("open source: %w", err)
	}
	if kind != documents.KindSource {
		return nil, nil, 0, fmt.Errorf("the container's source part is a %s", kind)
	}

	text, err := redact.Split(ctx, source)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(text) != len(pages) {
		return nil, nil, 0, fmt.Errorf("the document says %d pages and carries %d renders", len(text), len(pages))
	}

	found, missing := redact.Locate(text, fields)

	// A document whose pages carry no words at all is a picture, and nothing here can see where a
	// value is printed in one. The engine that read it can: it was shown those same pages. This is
	// the only way a scan gets a region, and a field the engine will not place stays missing.
	if redact.Textless(text) && locateScan != nil {
		ask := make(map[string]any, len(missing))
		for field := range missing {
			ask[field] = fields[field]
		}
		for field, box := range locateScan(ctx, ask, pages, text) {
			found[field] = box
		}
	}

	if len(found) == 0 {
		return nil, nil, 0, fmt.Errorf("%w (%s)", redact.ErrNoRegion, joinFields(missing))
	}
	if len(missing) > 0 {
		// Not fatal: a value the form reformats beyond recognition still leaves the rest of the page
		// redacted and reviewable. It is logged so the gap is visible rather than silent.
		log.Printf("document read-key: no region for %s; the page is redacted to the rest", joinFields(missing))
	}

	keeps := map[int][]redact.Box{}
	for _, box := range found {
		keeps[box.Page] = append(keeps[box.Page], box)
	}

	painted := make([][]byte, 0, len(pages))
	for index, page := range pages {
		number := index + 1
		// A page with nothing to keep comes back entirely painted out. That is the honest render: the
		// reviewer is told the document has pages that are none of their business, not handed a blank
		// sheet that looks like a page of nothing.
		black, err := redact.Black(page, text[index].Width, keeps[number])
		if err != nil {
			return nil, nil, 0, fmt.Errorf("redact page %d: %w", number, err)
		}
		painted = append(painted, black)
	}

	names := make([]string, 0, len(found))
	for field := range found {
		names = append(names, field)
	}
	sort.Strings(names)
	pieces = make([]docwire.Named, 0, len(names))
	for _, field := range names {
		box := found[field]
		piece, err := redact.Crop(pages[box.Page-1], text[box.Page-1].Width, box)
		if err != nil {
			log.Printf("document read-key: cannot cut %s: %v", field, err)
			continue
		}
		pieces = append(pieces, docwire.Named{Name: field, Bytes: piece})
	}

	return painted, pieces, len(found), nil
}

func joinFields(fields map[string]struct{}) string {
	names := make([]string, 0, len(fields))
	for field := range fields {
		names = append(names, field)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}
