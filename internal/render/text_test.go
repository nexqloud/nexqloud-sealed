package render

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeTextWriter writes a shell script that stands in for pdftotext: it prints the
// text given here to stdout, whatever its arguments were.
func fakeTextWriter(t *testing.T, text string, exitCode int) string {
	t.Helper()
	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	if text != "" {
		fmt.Fprintf(&script, "printf '%%s' '%s'\n", strings.NewReplacer("'", `'\''`, "\\", "\\\\").Replace(text))
	}
	if exitCode != 0 {
		script.WriteString("echo 'extractor exploded' >&2\n")
		fmt.Fprintf(&script, "exit %d\n", exitCode)
	}
	path := filepath.Join(t.TempDir(), "fake-text.sh")
	if err := os.WriteFile(path, []byte(script.String()), 0o755); err != nil {
		t.Fatalf("write fake extractor: %v", err)
	}
	return path
}

func TestExecTextReadsTheTextLayer(t *testing.T) {
	document := "CBP 7501 ENTRY SUMMARY\nHTS 8207301500\n\u000cPAGE TWO QUANTITY 1200"
	e := &ExecText{Command: fakeTextWriter(t, document, 0)}

	text, err := e.Text(context.Background(), []byte(pdfHeader), TextDefaults())
	if err != nil {
		t.Fatalf("Text: %v", err)
	}
	if text != document {
		t.Fatalf("text round-trip = %q", text)
	}

	pages := PageTexts(text)
	if len(pages) != 2 {
		t.Fatalf("got %d pages, want 2", len(pages))
	}
	if !strings.Contains(pages[1], "1200") {
		t.Fatalf("second page = %q", pages[1])
	}
}

func TestExecTextRefusesNonPDF(t *testing.T) {
	e := &ExecText{Command: fakeTextWriter(t, "text", 0)}

	for _, input := range [][]byte{nil, []byte("not a pdf"), []byte("x %PDF-1.4")} {
		if _, err := e.Text(context.Background(), input, TextDefaults()); !errors.Is(err, ErrNotPDF) {
			t.Fatalf("Text(%q) = %v, want ErrNotPDF", input, err)
		}
	}
}

func TestExecTextRefusesAScanAsAnAnswer(t *testing.T) {
	e := &ExecText{Command: fakeTextWriter(t, " \n\u000c\r\n ", 0)}

	if _, err := e.Text(context.Background(), []byte(pdfHeader), TextDefaults()); !errors.Is(err, ErrNoText) {
		t.Fatalf("Text of a scan = %v, want ErrNoText", err)
	}
}

func TestExecTextRefusesEmptyOutput(t *testing.T) {
	e := &ExecText{Command: fakeTextWriter(t, "", 0)}

	if _, err := e.Text(context.Background(), []byte(pdfHeader), TextDefaults()); !errors.Is(err, ErrNoText) {
		t.Fatalf("Text with no output = %v, want ErrNoText", err)
	}
}

func TestExecTextReportsExtractorFailure(t *testing.T) {
	e := &ExecText{Command: fakeTextWriter(t, "", 3)}

	_, err := e.Text(context.Background(), []byte(pdfHeader), TextDefaults())
	if err == nil {
		t.Fatal("Text succeeded although the extractor failed")
	}
	if !strings.Contains(err.Error(), "extractor exploded") {
		t.Fatalf("error does not carry the extractor's own message: %v", err)
	}
}

func TestExecTextEnforcesSizeLimit(t *testing.T) {
	e := &ExecText{Command: fakeTextWriter(t, strings.Repeat("A", 512), 0)}

	opts := TextDefaults()
	opts.MaxBytes = 64
	if _, err := e.Text(context.Background(), []byte(pdfHeader), opts); err == nil {
		t.Fatal("Text ignored MaxBytes")
	}
}

func TestExecTextReportsMissingExtractor(t *testing.T) {
	e := &ExecText{Command: filepath.Join(t.TempDir(), "nope")}

	if _, err := e.Text(context.Background(), []byte(pdfHeader), TextDefaults()); err == nil {
		t.Fatal("Text succeeded with no extractor present")
	}
}

func TestExecTextRefusesCanceledContext(t *testing.T) {
	e := &ExecText{Command: fakeTextWriter(t, "text", 0)}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	if _, err := e.Text(ctx, []byte(pdfHeader), TextDefaults()); err == nil {
		t.Fatal("Text succeeded with an expired context")
	}
}

func TestTextDefaultsAndOverrides(t *testing.T) {
	if got := TextDefaults(); got.MaxBytes != (TextOptions{}).withDefaults().MaxBytes {
		t.Fatalf("TextDefaults = %+v, want the same bounds as withDefaults", got)
	}
	custom := TextOptions{MaxBytes: 10, Timeout: time.Second}.withDefaults()
	if custom.MaxBytes != 10 || custom.Timeout != time.Second {
		t.Fatalf("withDefaults overwrote set values: %+v", custom)
	}
}

func TestDefaultTextCommandIsPoppler(t *testing.T) {
	if got := (&ExecText{}).command(); got != defaultTextCommand {
		t.Fatalf("command = %q, want %q", got, defaultTextCommand)
	}
}

func TestPageTextsDropsEmptyPages(t *testing.T) {
	pages := PageTexts("one\u000c\u000c  \u000ctwo")
	if len(pages) != 2 || pages[0] != "one" || pages[1] != "two" {
		t.Fatalf("PageTexts = %q", pages)
	}
}

func TestIsBlank(t *testing.T) {
	if !isBlank(" \n	\u000c\r\u00a0") {
		t.Fatal("whitespace-only text is not blank")
	}
	if isBlank("0") {
		t.Fatal("a digit is not blank")
	}
}
