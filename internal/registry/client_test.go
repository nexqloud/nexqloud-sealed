package registry_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"nexqloud-sealed/internal/registry"
)

func TestPutWrapSendsMaterialForOneOperator(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"stored":true}`))
	}))
	defer srv.Close()

	client := registry.NewHTTPClient(srv.URL)
	if err := client.PutWrap("ks1:abc", "operator-a", []byte("sealed-seed"), "sha256:deadbeef"); err != nil {
		t.Fatal(err)
	}

	if gotMethod != http.MethodPut {
		t.Fatalf("method = %s, want PUT", gotMethod)
	}
	if gotPath != "/records/ks1:abc/wraps/operator-a" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotBody["operator_id"] != "operator-a" || gotBody["seed_commit"] != "sha256:deadbeef" {
		t.Fatalf("unexpected body: %v", gotBody)
	}
	decoded, err := base64.StdEncoding.DecodeString(gotBody["wrap"].(string))
	if err != nil || string(decoded) != "sealed-seed" {
		t.Fatalf("wrap not carried as base64: %v (%v)", gotBody["wrap"], err)
	}
}

func TestDestroyWrapIssuesDelete(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"destroyed":true}`))
	}))
	defer srv.Close()

	client := registry.NewHTTPClient(srv.URL)
	if err := client.DestroyWrap("ks1:abc", "operator-a"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method = %s, want DELETE", gotMethod)
	}
	if gotPath != "/records/ks1:abc/wraps/operator-a" {
		t.Fatalf("path = %s", gotPath)
	}
}

func TestPutWrapRejectsEmptyInput(t *testing.T) {
	client := registry.NewHTTPClient("http://127.0.0.1:1")
	if err := client.PutWrap("ks1:abc", "operator-a", nil, "sha256:x"); err == nil {
		t.Fatal("expected error when the wrap is empty")
	}
	if err := client.PutWrap("", "operator-a", []byte("w"), ""); err == nil {
		t.Fatal("expected error when tenant_id is empty")
	}
}

func TestPutWrapSurfacesRegistryError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "seed_commit mismatch", http.StatusConflict)
	}))
	defer srv.Close()

	client := registry.NewHTTPClient(srv.URL)
	err := client.PutWrap("ks1:abc", "operator-a", []byte("w"), "sha256:x")
	if err == nil {
		t.Fatal("expected the registry error to surface")
	}
}
