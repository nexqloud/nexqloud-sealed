package blobfetch

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchReadsTheObject(t *testing.T) {
	body := []byte("sealed bytes, unreadable to anyone")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		w.Write(body)
	}))
	defer srv.Close()

	f := &Fetcher{AllowPlainHTTP: true}
	got, err := f.Fetch(context.Background(), srv.URL+"/case/source.pdf")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("Fetch = %q", got)
	}
}

func TestFetchRefusesPlainHTTPUnlessAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nope"))
	}))
	defer srv.Close()

	f := &Fetcher{}
	if _, err := f.Fetch(context.Background(), srv.URL); !errors.Is(err, ErrBadURL) {
		t.Fatalf("Fetch over http = %v, want ErrBadURL", err)
	}
}

func TestFetchAcceptsHTTPS(t *testing.T) {
	body := []byte("sealed bytes")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	f := &Fetcher{Client: srv.Client()}
	got, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("Fetch = %q", got)
	}
}

func TestFetchRefusesBadURLs(t *testing.T) {
	f := &Fetcher{AllowPlainHTTP: true}

	cases := map[string]string{
		"empty":          "",
		"no host":        "https:///path",
		"ftp":            "ftp://example.com/x",
		"file":           "file:///etc/passwd",
		"with userinfo":  "https://user:pass@example.com/x",
		"garbage scheme": "::::",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := f.Fetch(context.Background(), raw); err == nil {
				t.Fatalf("Fetch(%q) succeeded", raw)
			}
		})
	}
}

func TestFetchRefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("reached the redirect target"))
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()

	f := &Fetcher{AllowPlainHTTP: true}
	_, err := f.Fetch(context.Background(), srv.URL)
	if !errors.Is(err, ErrBadStatus) {
		t.Fatalf("Fetch following a redirect = %v, want ErrBadStatus", err)
	}
}

func TestFetchReportsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "NoSuchKey", http.StatusNotFound)
	}))
	defer srv.Close()

	f := &Fetcher{AllowPlainHTTP: true}
	_, err := f.Fetch(context.Background(), srv.URL)
	if !errors.Is(err, ErrBadStatus) {
		t.Fatalf("Fetch of a missing object = %v, want ErrBadStatus", err)
	}
}

func TestFetchEnforcesSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("x"), 4096))
	}))
	defer srv.Close()

	f := &Fetcher{AllowPlainHTTP: true, MaxBytes: 64}
	if _, err := f.Fetch(context.Background(), srv.URL); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch of an oversized object = %v, want ErrTooLarge", err)
	}
}

func TestFetchRefusesOversizedDeclaredLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "999999999")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("small really"))
	}))
	defer srv.Close()

	f := &Fetcher{AllowPlainHTTP: true, MaxBytes: 1024}
	if _, err := f.Fetch(context.Background(), srv.URL); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch of a lying Content-Length = %v, want ErrTooLarge", err)
	}
}

func TestFetchRefusesEmptyObject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := &Fetcher{AllowPlainHTTP: true}
	if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("Fetch of an empty object succeeded")
	}
}

func TestFetchHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	f := &Fetcher{AllowPlainHTTP: true}
	if _, err := f.Fetch(ctx, srv.URL); err == nil {
		t.Fatal("Fetch succeeded with a canceled context")
	}
}
