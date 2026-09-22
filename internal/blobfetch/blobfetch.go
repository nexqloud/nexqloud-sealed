// Package blobfetch pulls sealed bytes from object storage over a presigned URL.
//
// It holds no credentials on purpose: the URL is the capability, and the caller
// mints it. That is safe because what comes back is ciphertext, and ciphertext
// authenticates itself — a stale link, a swapped object or a hostile host can
// only ever deliver bytes that fail the AEAD tag. The fetcher's job is not to
// decide whether the bytes are trustworthy; it is to bound what a bad URL can
// cost — no redirects, no plaintext transport, a size cap and a deadline.
package blobfetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrBadURL    = errors.New("blobfetch: refusing url")
	ErrTooLarge  = errors.New("blobfetch: object exceeds the size limit")
	ErrBadStatus = errors.New("blobfetch: unexpected status")
)

// Fetcher reads one object per call.
type Fetcher struct {
	// Client is the HTTP client to use. Empty means one that refuses redirects
	// and gives up after Timeout.
	Client *http.Client
	// MaxBytes is the largest object to accept. Zero means 512 MiB.
	MaxBytes int64
	// AllowPlainHTTP permits http:// URLs. Local object storage in development
	// needs it; production must not set it.
	AllowPlainHTTP bool
	// Timeout bounds one fetch. Zero means 60s.
	Timeout time.Duration
}

func (f *Fetcher) maxBytes() int64 {
	if f.MaxBytes > 0 {
		return f.MaxBytes
	}
	return 512 << 20
}

func (f *Fetcher) timeout() time.Duration {
	if f.Timeout > 0 {
		return f.Timeout
	}
	return 60 * time.Second
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{
		Timeout: f.timeout(),
		// A redirect is a way to leave the scheme we allowed. Surface it instead.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Fetch reads the object the URL points at.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadURL, err)
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !f.AllowPlainHTTP {
			return nil, fmt.Errorf("%w: plain http is not allowed", ErrBadURL)
		}
	default:
		return nil, fmt.Errorf("%w: scheme %q", ErrBadURL, parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: no host", ErrBadURL)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("%w: credentials in the url", ErrBadURL)
	}

	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadURL, err)
	}

	resp, err := f.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("blobfetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// The body of a failure is the storage provider's, not ours; read a little
		// for the error message and drop the rest.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%w: %d %s", ErrBadStatus, resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	limit := f.maxBytes()
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("%w: %d bytes declared", ErrTooLarge, resp.ContentLength)
	}

	blob, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("blobfetch: read: %w", err)
	}
	if int64(len(blob)) > limit {
		return nil, fmt.Errorf("%w: over %d bytes", ErrTooLarge, limit)
	}
	if len(blob) == 0 {
		return nil, fmt.Errorf("blobfetch: empty object")
	}
	return blob, nil
}
