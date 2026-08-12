package wipe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEraseSlotsOK(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/slots", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Fatalf("unexpected query on GET /slots: %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`[{"id":0},{"id":1}]`))
	})
	mux.HandleFunc("/slots/0", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") != "erase" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/slots/1", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") != "erase" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ids, err := EraseSlots(srv.URL, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != 0 || ids[1] != 1 {
		t.Fatalf("ids=%v", ids)
	}
}

func TestEraseSlotsBusyThenOK(t *testing.T) {
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/slots", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":0}]`))
	})
	mux.HandleFunc("/slots/0", func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			http.Error(w, "slot is busy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ids, err := EraseSlots(srv.URL, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != 0 {
		t.Fatalf("ids=%v", ids)
	}
	if calls.Load() < 2 {
		t.Fatalf("expected retry, calls=%d", calls.Load())
	}
}

func TestEraseSlotsHardFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/slots", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":0}]`))
	})
	mux.HandleFunc("/slots/0", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := EraseSlots(srv.URL, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestEraseSlotsWrappedShape(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/slots", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"slots":[{"id_slot":0}]}`))
	})
	mux.HandleFunc("/slots/0", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ids, err := EraseSlots(srv.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != 0 {
		t.Fatalf("ids=%v", ids)
	}
}

func TestEraseSlotsDefaultsToZeroWhenEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/slots", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/slots/0", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ids, err := EraseSlots(srv.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != 0 {
		t.Fatalf("ids=%v", ids)
	}
}
