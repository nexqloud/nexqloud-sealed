package main

import (
	"bytes"
	"testing"

	"nexqloud-sealed/internal/readkey"
	"nexqloud-sealed/pkg/docwire"
)

// The bug this guards: the pages were sealed and the pieces were not, so a "redacted" document
// travelled with legible regions of it in the clear, in the same container as the sealed pages.
func TestEveryPartGoingToARecipientIsSealed(t *testing.T) {
	key, err := readkey.NewSessionKey()
	if err != nil {
		t.Fatalf("session key: %v", err)
	}
	page := []byte("\x89PNG\r\n\x1a\n a page render, which is a picture of somebody's paperwork")
	piece := []byte("\x89PNG\r\n\x1a\n the region of it under review")

	pages, pieces, err := sealForRecipient(key, [][]byte{page}, []docwire.Named{{Name: "importer_of_record", Bytes: piece}})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(pages) != 1 || len(pieces) != 1 {
		t.Fatalf("want one sealed page and one sealed piece, got %d and %d", len(pages), len(pieces))
	}
	if pieces[0].Name != "importer_of_record" {
		t.Fatalf("the piece has to keep its name, got %q", pieces[0].Name)
	}

	for name, blob := range map[string][]byte{"page": pages[0], "piece": pieces[0].Bytes} {
		if bytes.HasPrefix(blob, []byte("\x89PNG")) {
			t.Errorf("the %s went out as a plain PNG", name)
		}
	}

	// And the recipient can still open both with the session key, so sealing is not just mangling.
	pageBack, err := readkey.OpenPage(key, pages[0])
	if err != nil || !bytes.Equal(pageBack, page) {
		t.Errorf("the sealed page does not open: %v", err)
	}
	pieceBack, err := readkey.OpenPage(key, pieces[0].Bytes)
	if err != nil || !bytes.Equal(pieceBack, piece) {
		t.Errorf("the sealed piece does not open: %v", err)
	}
}
