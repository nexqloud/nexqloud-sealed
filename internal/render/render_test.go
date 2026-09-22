package render

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const pdfHeader = "%PDF-1.4\nfake pdf body\n"

// fakeConverter writes a shell script that stands in for poppler: it creates the
// page files the shim expects, from the page list baked in here.
func fakeConverter(t *testing.T, pages []string, exitCode int) string {
	t.Helper()
	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	script.WriteString("out=\"$5\"\n")
	for _, page := range pages {
		fmt.Fprintf(&script, "printf '\\211PNG\\r\\n\\032\\n%s' > \"$out-%s.png\"\n", page, page)
	}
	if exitCode != 0 {
		script.WriteString("echo 'converter exploded' >&2\n")
		fmt.Fprintf(&script, "exit %d\n", exitCode)
	}
	path := filepath.Join(t.TempDir(), "fake-converter.sh")
	if err := os.WriteFile(path, []byte(script.String()), 0o755); err != nil {
		t.Fatalf("write fake converter: %v", err)
	}
	return path
}

func TestExecRendersPagesInOrder(t *testing.T) {
	// Written out of order on purpose: page 10 must not sort between 1 and 2.
	converter := fakeConverter(t, []string{"10", "2", "1"}, 0)
	e := &Exec{Command: converter}

	pages, err := e.Pages(context.Background(), []byte(pdfHeader), DefaultOptions())
	if err != nil {
		t.Fatalf("Pages: %v", err)
	}
	if len(pages) != 3 {
		t.Fatalf("got %d pages, want 3", len(pages))
	}
	for i, want := range []string{"1", "2", "10"} {
		if !bytes.Contains(pages[i], []byte(want)) {
			t.Fatalf("page %d is not page %s", i+1, want)
		}
		if !bytes.HasPrefix(pages[i], []byte(pngSignature)) {
			t.Fatalf("page %d is not a PNG", i+1)
		}
	}
}

func TestExecRefusesNonPDF(t *testing.T) {
	e := &Exec{Command: fakeConverter(t, []string{"1"}, 0)}

	for _, input := range [][]byte{nil, []byte("not a pdf at all"), []byte(" %PDF-1.4 leading space")} {
		if _, err := e.Pages(context.Background(), input, DefaultOptions()); !errors.Is(err, ErrNotPDF) {
			t.Fatalf("Pages(%q) = %v, want ErrNotPDF", input, err)
		}
	}
}

func TestExecReportsConverterFailure(t *testing.T) {
	e := &Exec{Command: fakeConverter(t, nil, 2)}

	_, err := e.Pages(context.Background(), []byte(pdfHeader), DefaultOptions())
	if err == nil {
		t.Fatal("Pages succeeded although the converter failed")
	}
	if !strings.Contains(err.Error(), "converter exploded") {
		t.Fatalf("error does not carry the converter's own message: %v", err)
	}
}

func TestExecRefusesNoPages(t *testing.T) {
	e := &Exec{Command: fakeConverter(t, nil, 0)}

	if _, err := e.Pages(context.Background(), []byte(pdfHeader), DefaultOptions()); !errors.Is(err, ErrNoPages) {
		t.Fatalf("Pages with no output = %v, want ErrNoPages", err)
	}
}

func TestExecRefusesNonPNGOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "liar.sh")
	script := "#!/bin/sh\nprintf 'not an image' > \"$5-1.png\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := &Exec{Command: path}
	if _, err := e.Pages(context.Background(), []byte(pdfHeader), DefaultOptions()); !errors.Is(err, ErrNotPNG) {
		t.Fatalf("Pages with non-PNG output = %v, want ErrNotPNG", err)
	}
}

func TestExecEnforcesPageLimit(t *testing.T) {
	e := &Exec{Command: fakeConverter(t, []string{"1", "2", "3"}, 0)}

	opts := DefaultOptions()
	opts.MaxPages = 2
	if _, err := e.Pages(context.Background(), []byte(pdfHeader), opts); err == nil {
		t.Fatal("Pages ignored MaxPages")
	}
}

func TestExecEnforcesByteLimit(t *testing.T) {
	e := &Exec{Command: fakeConverter(t, []string{"1", "2"}, 0)}

	opts := DefaultOptions()
	opts.MaxBytes = 4
	if _, err := e.Pages(context.Background(), []byte(pdfHeader), opts); err == nil {
		t.Fatal("Pages ignored MaxBytes")
	}
}

func TestExecReportsMissingConverter(t *testing.T) {
	e := &Exec{Command: filepath.Join(t.TempDir(), "does-not-exist")}

	if _, err := e.Pages(context.Background(), []byte(pdfHeader), DefaultOptions()); err == nil {
		t.Fatal("Pages succeeded with no converter present")
	}
}

func TestExecRefusesCanceledContext(t *testing.T) {
	e := &Exec{Command: fakeConverter(t, []string{"1"}, 0)}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	if _, err := e.Pages(ctx, []byte(pdfHeader), DefaultOptions()); err == nil {
		t.Fatal("Pages succeeded with an expired context")
	}
}

func TestOptionsWithDefaults(t *testing.T) {
	got := Options{}.withDefaults()
	want := DefaultOptions()
	if got != want {
		t.Fatalf("withDefaults = %+v, want %+v", got, want)
	}
	if got := (Options{DPI: 50, MaxPages: 1, MaxBytes: 2, Timeout: time.Second}).withDefaults(); got.DPI != 50 {
		t.Fatal("withDefaults overwrote a set value")
	}
}

func TestDefaultCommandIsPoppler(t *testing.T) {
	if got := (&Exec{}).command(); got != defaultCommand {
		t.Fatalf("command = %q, want %q", got, defaultCommand)
	}
}
