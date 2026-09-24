// Package redact shows a reviewer the parts of a document that concern them, and nothing else.
//
// The requirement, in the words it was given in: keep every region the tariff math reads and the
// fields on the review screen, and put a black rectangle over the rest. The application cannot do
// this — it holds ciphertext and a pointer — so it happens here, where the plaintext is, before a
// page render is sealed to the person who asked to see it.
//
// A region is found from the document's own text layer: the words poppler reports for a page, with
// the boxes they occupy. That is also the honest boundary of this package — a scan has no text to
// find anything in, so nothing there can be located, and saying so beats cutting a rectangle over a
// guess.
//
// One coordinate space, deliberately: poppler reports boxes in points with the origin at the top
// left, which is also an image's space. So the page's own width, taken from the extraction and from
// the render, is the only scale factor here, and there is no vertical flip to get wrong. (The
// application's copy of this algorithm reads pages through a library whose boxes measure y upwards;
// that difference is where its first crop landed on the wrong caption.)
package redact

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

const (
	// MarginPt is the air left around a kept region. A rectangle tight enough to clip a descender is
	// one that makes the person reading it doubt what they are looking at.
	MarginPt = 12.0
	// MinDigits is the length below which a number is not searched for at all: `2` packages or `757`
	// would match something else on the page, and the wrong region is worse than no region.
	MinDigits = 4
)

var (
	// ErrNoText is a page with nothing to locate a value in — a scan, in this corpus.
	ErrNoText = errors.New("redact: this document carries no text to find a value in")
	// ErrNoRegion is a page where none of the values under review could be found.
	ErrNoRegion = errors.New("redact: none of the values under review could be located")
)

// Word is one word as the document prints it, with the box it occupies.
type Word struct {
	Text                     string
	Left, Top, Right, Bottom float64
}

// Page is one page's words, in the page's own points with the origin at the top left.
type Page struct {
	Number        int
	Width, Height float64
	Words         []Word
}

// Box is a region on one page, in the same space as Word.
type Box struct {
	Page                     int
	Left, Top, Right, Bottom float64
}

// grown returns the box with a margin around it, clamped to the page's own edges.
func (b Box) grown(margin, width, height float64) Box {
	return Box{
		Page:   b.Page,
		Left:   math.Max(0, b.Left-margin),
		Top:    math.Max(0, b.Top-margin),
		Right:  math.Min(width, b.Right+margin),
		Bottom: math.Min(height, b.Bottom+margin),
	}
}

// Needle is one form of a stored value, and how to look for it.
type Needle struct {
	// Text is the value with everything but letters and digits removed, lower-cased. `12512.0`
	// therefore finds `$12,512.00`, and an ISO date finds the form's own MM/DD/YYYY.
	Text string
	// Numeric marks a needle that must not be found inside a longer number: `12512` is not `112512`.
	Numeric bool
	// Continuation marks a further line of a value that is printed across several: a stored importer
	// of record carries the street and the city on their own lines, and the region a reviewer is
	// shown should be the whole block and not only its first line.
	Continuation bool
}

// Needles lists the forms of a stored value worth looking for, most specific first.
//
// A stored value is what the reviewer is shown, which is not always what the page prints.
func Needles(value any) []Needle {
	text := strings.TrimSpace(fmt.Sprint(value))
	cleaned := core(text)
	if cleaned == "" {
		return nil
	}

	if number, err := strconv.ParseFloat(text, 64); err == nil {
		var out []Needle
		if number == math.Trunc(number) {
			whole := strconv.FormatInt(int64(number), 10)
			if len(whole) >= MinDigits {
				out = append(out, Needle{Text: whole, Numeric: true})
			}
		}
		// The form's own money format: 12,512.00 reads as 1251200 once the punctuation is gone.
		twoDP := strings.ReplaceAll(strconv.FormatFloat(number, 'f', 2, 64), ".", "")
		if len(twoDP) >= MinDigits {
			out = append(out, Needle{Text: twoDP, Numeric: true})
		}
		return out
	}

	// A value stored across several lines is looked for line by line: the address of an importer is
	// one field but three printed lines, and the region should cover all of them.
	if strings.ContainsAny(text, "\n\r") {
		var out []Needle
		for _, line := range strings.Split(strings.ReplaceAll(text, "\r", "\n"), "\n") {
			printed := core(line)
			if len(printed) < 4 {
				// A line too short to look for on its own — a stray number, or `IL` — still belongs to
				// the region, and the lines that could be found will cover it.
				continue
			}
			out = append(out, Needle{Text: printed, Continuation: len(out) > 0})
		}
		return out
	}

	var out []Needle
	if len(text) == 10 && text[4] == '-' && text[7] == '-' {
		year, month, day := text[0:4], text[5:7], text[8:10]
		out = append(out,
			Needle{Text: month + day + year, Numeric: true},
			Needle{Text: day + month + year, Numeric: true},
		)
	}
	if len(cleaned) >= 4 {
		out = append(out, Needle{Text: cleaned})
		return out
	}
	if len(cleaned) >= 3 {
		// Short and alphabetic: `AIR` or `LCL` is findable, but a two-letter value would land in the
		// middle of some other word, so below three there is nothing to look for.
		out = append(out, Needle{Text: cleaned})
	}
	return out
}

// core is a value with everything but letters and digits removed, lower-cased.
func core(text string) string {
	var out []rune
	for _, r := range strings.ToLower(text) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			out = append(out, r)
		}
	}
	return string(out)
}

func digits(text string) bool {
	for _, r := range text {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return text != ""
}

// Match finds each value on one page. It is pure — no process, no file, no image — so the ladder
// that decides which region a value lives in is testable on its own.
func Match(page Page, values map[string]any) map[string]Box {
	// The page's letters and digits as one string, with every character remembering which word it
	// came from. A value spanning several words then comes out as one box over all of them.
	var letters []rune
	var owner []int
	for index, word := range page.Words {
		for _, r := range core(word.Text) {
			letters = append(letters, r)
			owner = append(owner, index)
		}
	}
	hay := string(letters)

	found := map[string]Box{}
	for field, value := range values {
		needles := Needles(value)
		for index, needle := range needles {
			if needle.Continuation {
				continue
			}
			at := find(hay, owner, needle)
			if at < 0 {
				continue
			}
			box, ok := union(page, owner[at:at+len([]rune(needle.Text))])
			if !ok {
				continue
			}
			// The rest of a value printed across lines joins the same region, so a reviewer sees the
			// whole of what was read and not one line of it.
			for _, next := range needles[index+1:] {
				if !next.Continuation {
					continue
				}
				at := find(hay, owner, next)
				if at < 0 {
					continue
				}
				more, ok := union(page, owner[at:at+len([]rune(next.Text))])
				if !ok {
					continue
				}
				box = covering(box, more)
			}
			found[field] = box
			break
		}
	}
	return found
}

// find locates a needle. A number has to be a whole word — `12512` is not the `12512` inside
// `112512`, and that region is somebody else's value. The whole-word rule is what makes this safe
// even though one word's digits run straight into the next word's in the joined string.
//
// Letters are not held to it: a form prints `THE HARDWARE DEPOT, INC.` while the reviewer is shown
// the value as it was stored, so requiring a word boundary would reject the region actually wanted.
func find(hay string, owner []int, needle Needle) int {
	// Runes throughout: a byte offset is not a position in this string, and a page may hold letters
	// that are more than one byte long.
	text := []rune(needle.Text)
	runes := []rune(hay)
	at := indexRunes(runes, text, 0)
	if !needle.Numeric {
		return at
	}
	for at >= 0 {
		last := at + len(text)
		startsAWord := at == 0 || owner[at-1] != owner[at]
		endsAWord := last >= len(owner) || owner[last] != owner[last-1]
		if startsAWord && endsAWord {
			return at
		}
		at = indexRunes(runes, text, at+1)
	}
	return -1
}

// indexRunes is strings.Index over runes, which is the only space these offsets are meaningful in.
func indexRunes(hay, needle []rune, from int) int {
	if len(needle) == 0 || from < 0 || from > len(hay) {
		return -1
	}
	for start := from; start+len(needle) <= len(hay); start++ {
		match := true
		for offset := range needle {
			if hay[start+offset] != needle[offset] {
				match = false
				break
			}
		}
		if match {
			return start
		}
	}
	return -1
}

// covering is the smallest box holding both.
func covering(a, b Box) Box {
	return Box{
		Page:   a.Page,
		Left:   math.Min(a.Left, b.Left),
		Top:    math.Min(a.Top, b.Top),
		Right:  math.Max(a.Right, b.Right),
		Bottom: math.Max(a.Bottom, b.Bottom),
	}
}

// union is the smallest box covering the words a match spans.
func union(page Page, words []int) (Box, bool) {
	box := Box{Page: page.Number, Left: math.MaxFloat64, Top: math.MaxFloat64}
	seen := false
	for _, index := range words {
		if index < 0 || index >= len(page.Words) {
			continue
		}
		word := page.Words[index]
		box.Left = math.Min(box.Left, word.Left)
		box.Top = math.Min(box.Top, word.Top)
		box.Right = math.Max(box.Right, word.Right)
		box.Bottom = math.Max(box.Bottom, word.Bottom)
		seen = true
	}
	if !seen {
		return Box{}, false
	}
	return box, true
}

// Textless reports a document whose pages carry no words at all — a scan.
//
// Such a page has no source of a location here, and asking for one from the text layer would find
// nothing; the caller has to get the boxes from what the model saw instead, and this is how it knows
// to ask rather than sending a page it cannot redact.
func Textless(pages []Page) bool {
	if len(pages) == 0 {
		return false
	}
	for _, page := range pages {
		if len(page.Words) > 0 {
			return false
		}
	}
	return true
}

// NormalisedBox puts a box a model gave for a page it was shown into the page's own points.
//
// A model answers about the picture it was given, so its numbers are fractions of that picture's
// width and height from its top left — the same corner poppler measures from, so nothing is flipped
// here. The page's own size comes from the document, not from the image, because the two need not be
// drawn at the same scale.
func NormalisedBox(page int, x, y, width, height, pageWidth, pageHeight float64) Box {
	clamp := func(value, limit float64) float64 {
		if value < 0 {
			return 0
		}
		if value > limit {
			return limit
		}
		return value
	}
	left := clamp(x, 1.0) * pageWidth
	top := clamp(y, 1.0) * pageHeight
	right := clamp(x+width, 1.0) * pageWidth
	bottom := clamp(y+height, 1.0) * pageHeight
	return Box{Page: page, Left: left, Top: top, Right: right, Bottom: bottom}
}

// Splitter reads a document's words and the boxes they occupy on each page.
//
// It exists so the two sides of the product can be tested without a real document, and so a
// deployment that reads words another way can be swapped in: everything above it deals in pages of
// words, not in how they were obtained.
type Splitter interface {
	Pages(ctx context.Context, source []byte) ([]Page, error)
}

// Exec is the splitter the guest provides: poppler's own words, read from the document the enclave
// holds. A page with no words is still a page here — it has a size and no text, which is what a scan
// is — so this reports the failure to read the document rather than the absence of text.
type Exec struct{}

// Pages reads the words and boxes of every page.
func (Exec) Pages(ctx context.Context, source []byte) ([]Page, error) { return Split(ctx, source) }

// Split asks the document what it says and where. This is the only step that leaves the process.
func Split(ctx context.Context, source []byte) ([]Page, error) {
	dir, err := os.MkdirTemp("", "redact-")
	if err != nil {
		return nil, fmt.Errorf("redact: temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "source.pdf")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		return nil, fmt.Errorf("redact: write source: %w", err)
	}
	// -bbox reports one box per word in points from the top left; poppler-utils is already in this
	// image because the renderer draws the pages with pdftoppm from the same package.
	out, err := exec.CommandContext(ctx, "pdftotext", "-q", "-bbox", path, "-").Output()
	if err != nil {
		return nil, fmt.Errorf("redact: pdftotext: %w", err)
	}
	return parseBBox(out)
}

type bboxWord struct {
	Text  string  `xml:"-"`
	Chars string  `xml:",chardata"`
	XMin  float64 `xml:"xMin,attr"`
	YMin  float64 `xml:"yMin,attr"`
	XMax  float64 `xml:"xMax,attr"`
	YMax  float64 `xml:"yMax,attr"`
}

type bboxPage struct {
	Width  float64    `xml:"width,attr"`
	Height float64    `xml:"height,attr"`
	Words  []bboxWord `xml:"word"`
	Lines  []struct {
		Words []bboxWord `xml:"word"`
	} `xml:"line"`
}

type bboxDoc struct {
	Pages []bboxPage `xml:"body>doc>page"`
}

func parseBBox(raw []byte) ([]Page, error) {
	var doc bboxDoc
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("redact: parse text boxes: %w", err)
	}
	if len(doc.Pages) == 0 {
		return nil, ErrNoText
	}
	pages := make([]Page, 0, len(doc.Pages))
	for index, raw := range doc.Pages {
		page := Page{Number: index + 1, Width: raw.Width, Height: raw.Height}
		add := func(words []bboxWord) {
			for _, word := range words {
				text := strings.TrimSpace(word.Chars)
				if text == "" {
					continue
				}
				page.Words = append(page.Words, Word{
					Text: text, Left: word.XMin, Top: word.YMin, Right: word.XMax, Bottom: word.YMax,
				})
			}
		}
		add(raw.Words)
		for _, line := range raw.Lines {
			add(line.Words)
		}
		pages = append(pages, page)
	}
	return pages, nil
}

// Locate finds every value it can and reports the ones it cannot, so a caller can be honest about
// what a reviewer is not being shown rather than quietly omitting it.
func Locate(pages []Page, values map[string]any) (map[string]Box, map[string]struct{}) {
	found := map[string]Box{}
	for _, page := range pages {
		for field, box := range Match(page, values) {
			if _, done := found[field]; !done {
				found[field] = box
			}
		}
	}
	missing := map[string]struct{}{}
	for field := range values {
		if _, ok := found[field]; !ok {
			missing[field] = struct{}{}
		}
	}
	return found, missing
}

// Black paints out everything on a page render except the regions named. Nothing else leaves the
// enclave: the person who asked is handed the page with the rest of it gone, so that a reviewer can
// tell at a glance that the document has parts they are not being shown.
func Black(render []byte, pageWidth float64, keeps []Box) ([]byte, error) {
	img, err := decode(render)
	if err != nil {
		return nil, err
	}
	bounds := img.Bounds()
	scale := float64(bounds.Dx()) / pageWidth
	// The render's own aspect is the page height, so a margin is clamped to the page and not to zero.
	pageHeight := float64(bounds.Dy()) / scale
	dst := image.NewRGBA(bounds)
	draw.Draw(dst, bounds, image.NewUniform(color.Black), image.Point{}, draw.Src)
	for _, box := range keeps {
		rect := pixelRect(box.grown(MarginPt, pageWidth, pageHeight), scale, bounds)
		if rect.Empty() {
			continue
		}
		draw.Draw(dst, rect, img, rect.Min, draw.Src)
	}
	var out bytes.Buffer
	if err := png.Encode(&out, dst); err != nil {
		return nil, fmt.Errorf("redact: encode page: %w", err)
	}
	return out.Bytes(), nil
}

// Crop cuts one region out of a page render, for a reviewer who wants to look at one value closely.
func Crop(render []byte, pageWidth float64, box Box) ([]byte, error) {
	img, err := decode(render)
	if err != nil {
		return nil, err
	}
	bounds := img.Bounds()
	scale := float64(bounds.Dx()) / pageWidth
	pageHeight := float64(bounds.Dy()) / scale
	rect := pixelRect(box.grown(MarginPt, pageWidth, pageHeight), scale, bounds)
	if rect.Empty() {
		return nil, ErrNoRegion
	}
	dst := image.NewRGBA(image.Rect(0, 0, rect.Dx(), rect.Dy()))
	draw.Draw(dst, dst.Bounds(), img, rect.Min, draw.Src)
	var out bytes.Buffer
	if err := png.Encode(&out, dst); err != nil {
		return nil, fmt.Errorf("redact: encode piece: %w", err)
	}
	return out.Bytes(), nil
}

func decode(render []byte) (image.Image, error) {
	img, _, err := image.Decode(bytes.NewReader(render))
	if err != nil {
		return nil, fmt.Errorf("redact: decode page render: %w", err)
	}
	return img, nil
}

// pixelRect takes a box in page points to the pixels of a render, whose own width gives the scale.
func pixelRect(box Box, scale float64, bounds image.Rectangle) image.Rectangle {
	rect := image.Rect(
		int(math.Round(box.Left*scale)),
		int(math.Round(box.Top*scale)),
		int(math.Round(box.Right*scale)),
		int(math.Round(box.Bottom*scale)),
	)
	return rect.Intersect(bounds)
}
