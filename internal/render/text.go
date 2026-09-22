package render

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrNoText means the document has no text layer to read — a scan, most likely.
// It is an answer, not a failure: the caller should route it to review rather than
// pretend the page was empty of values.
var ErrNoText = errors.New("render: document has no text layer")

const (
	defaultTextCommand = "pdftotext"
	// textLimit bounds one document's text. A few hundred pages of a customs
	// bundle fits; a decompression bomb does not.
	textLimit = 8 << 20
)

// TextOptions bounds one text extraction.
type TextOptions struct {
	MaxBytes int
	Timeout  time.Duration
}

// TextDefaults is the bound a document fits inside.
func TextDefaults() TextOptions {
	return TextOptions{MaxBytes: textLimit, Timeout: 120 * time.Second}
}

func (o TextOptions) withDefaults() TextOptions {
	if o.MaxBytes <= 0 {
		o.MaxBytes = textLimit
	}
	if o.Timeout <= 0 {
		o.Timeout = 120 * time.Second
	}
	return o
}

// TextExtractor reads the text layer of a PDF.
type TextExtractor interface {
	Text(ctx context.Context, pdf []byte, opts TextOptions) (string, error)
}

// ExecText reads text by running poppler's pdftotext inside the guest.
//
// Layout is preserved because a customs form is a table: without it, a part number
// and the quantity beside it arrive with no relationship to each other.
type ExecText struct {
	// Command is the extractor to run. Empty means poppler's pdftotext.
	Command string
	// TempDir is where the working directory is created. Empty means os.TempDir;
	// a RAM-backed path keeps the document off the guest's disk.
	TempDir string
}

func (e *ExecText) command() string {
	if strings.TrimSpace(e.Command) != "" {
		return e.Command
	}
	return defaultTextCommand
}

func (e *ExecText) Text(ctx context.Context, pdf []byte, opts TextOptions) (string, error) {
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		return "", ErrNotPDF
	}
	opts = opts.withDefaults()

	dir, err := os.MkdirTemp(e.TempDir, "text-*")
	if err != nil {
		return "", fmt.Errorf("render: working directory: %w", err)
	}
	defer os.RemoveAll(dir)

	input := filepath.Join(dir, "input.pdf")
	if err := os.WriteFile(input, pdf, 0o600); err != nil {
		return "", fmt.Errorf("render: write input: %w", err)
	}
	defer os.Remove(input)

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	// "-" is poppler's own spelling for "write to stdout", so no plaintext page
	// text is left behind in a file.
	cmd := exec.CommandContext(ctx, e.command(), "-layout", input, "-")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("render: %s: %w: %s", e.command(), err, strings.TrimSpace(stderr.String()))
	}
	if stdout.Len() > opts.MaxBytes {
		return "", fmt.Errorf("render: text exceeds the %d-byte limit", opts.MaxBytes)
	}

	text := stdout.String()
	if isBlank(text) {
		return "", ErrNoText
	}
	return text, nil
}

// isBlank reports whether extracted text carries no readable content. poppler
// answers a scanned page with page breaks and whitespace, and calling that a read
// document is the kind of claim this platform exists to avoid.
func isBlank(text string) bool {
	for _, r := range text {
		switch r {
		case ' ', '\t', '\r', '\n', '\f', '\v', 0x00a0, 0xfeff:
		default:
			return false
		}
	}
	return true
}

// PageTexts splits an extractor's output into pages. poppler marks a page break
// with a form feed, which is also what the extraction prompt tells the model to
// expect.
func PageTexts(text string) []string {
	raw := strings.Split(text, "\f")
	pages := make([]string, 0, len(raw))
	for _, page := range raw {
		if strings.TrimSpace(page) == "" {
			continue
		}
		pages = append(pages, page)
	}
	return pages
}
