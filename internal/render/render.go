// Package render turns a PDF into page images inside the enclosure.
//
// The render must happen here rather than in the calling application: a page
// image is the plaintext of the document in picture form, so anything that draws
// one has the document. The sealed guest image pins the converter binary — a
// sibling process inside the same guest, reached by exec — and this package only
// needs to know where it is.
//
// The input is written to a temporary file because the converter takes a path.
// That file is inside the guest and is removed as soon as the render finishes;
// point TempDir at a RAM-backed path so a plaintext page never touches the guest's
// disk at all.
package render

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrNotPDF  = errors.New("render: input is not a PDF")
	ErrNoPages = errors.New("render: converter produced no pages")
	ErrNotPNG  = errors.New("render: converter produced something that is not a PNG")
)

const (
	defaultCommand = "pdftoppm"
	pngSignature   = "\x89PNG\r\n\x1a\n"
)

// Options bounds a single render.
type Options struct {
	DPI      int
	MaxPages int
	MaxBytes int
	Timeout  time.Duration
}

// DefaultOptions is a bound that a forty-page customs bundle fits inside and a
// hostile input does not.
func DefaultOptions() Options {
	return Options{DPI: 200, MaxPages: 50, MaxBytes: 512 << 20, Timeout: 120 * time.Second}
}

func (o Options) withDefaults() Options {
	if o.DPI <= 0 {
		o.DPI = 200
	}
	if o.MaxPages <= 0 {
		o.MaxPages = 50
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 512 << 20
	}
	if o.Timeout <= 0 {
		o.Timeout = 120 * time.Second
	}
	return o
}

// Renderer draws the pages of a PDF.
type Renderer interface {
	Pages(ctx context.Context, pdf []byte, opts Options) ([][]byte, error)
}

// Exec renders by running an external converter inside the guest — poppler's
// pdftoppm by default.
type Exec struct {
	// Command is the converter to run. Empty means poppler's pdftoppm.
	Command string
	// TempDir is where the working directory is created. Empty means os.TempDir.
	// A RAM-backed path is preferred: the input file is the document in plaintext.
	TempDir string
}

func (e *Exec) command() string {
	if strings.TrimSpace(e.Command) != "" {
		return e.Command
	}
	return defaultCommand
}

func (e *Exec) Pages(ctx context.Context, pdf []byte, opts Options) ([][]byte, error) {
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		return nil, ErrNotPDF
	}
	opts = opts.withDefaults()

	dir, err := os.MkdirTemp(e.TempDir, "render-*")
	if err != nil {
		return nil, fmt.Errorf("render: working directory: %w", err)
	}
	defer os.RemoveAll(dir)

	input := filepath.Join(dir, "input.pdf")
	if err := os.WriteFile(input, pdf, 0o600); err != nil {
		return nil, fmt.Errorf("render: write input: %w", err)
	}
	defer os.Remove(input)

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	prefix := filepath.Join(dir, "page")
	cmd := exec.CommandContext(ctx, e.command(),
		"-png",
		"-r", strconv.Itoa(opts.DPI),
		input,
		prefix,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("render: %s: %w: %s", e.command(), err, strings.TrimSpace(stderr.String()))
	}

	paths, err := pagePaths(dir)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, ErrNoPages
	}
	if len(paths) > opts.MaxPages {
		return nil, fmt.Errorf("render: %d pages exceeds the %d-page limit", len(paths), opts.MaxPages)
	}

	pages := make([][]byte, 0, len(paths))
	total := 0
	for _, path := range paths {
		page, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("render: read %s: %w", filepath.Base(path), err)
		}
		if !bytes.HasPrefix(page, []byte(pngSignature)) {
			return nil, fmt.Errorf("%w: %s", ErrNotPNG, filepath.Base(path))
		}
		total += len(page)
		if total > opts.MaxBytes {
			return nil, fmt.Errorf("render: rendered pages exceed the %d-byte limit", opts.MaxBytes)
		}
		pages = append(pages, page)
	}
	return pages, nil
}

// pagePaths lists the converter's output in page order. pdftoppm names its files
// page-1.png, page-2.png … page-10.png, so the sort has to read the number rather
// than the string, or page 10 lands between 1 and 2.
func pagePaths(dir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "page-*.png"))
	if err != nil {
		return nil, fmt.Errorf("render: list output: %w", err)
	}
	sort.Slice(matches, func(i, j int) bool {
		return pageNumber(matches[i]) < pageNumber(matches[j])
	})
	return matches, nil
}

func pageNumber(path string) int {
	base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "page-"), ".png")
	n, err := strconv.Atoi(base)
	if err != nil {
		return 1 << 30
	}
	return n
}
