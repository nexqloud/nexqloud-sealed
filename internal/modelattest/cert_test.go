package modelattest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHashFileAndSignRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.gguf")
	payload := []byte("gguf-fixture-bytes")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	want := "sha256:" + hex.EncodeToString(sum[:])

	got, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("HashFile=%q want %q", got, want)
	}

	cert := NewCert(got, "fixture", "nonce1", "issuer-a")
	signed, err := SignCert(cert, DevMockIssuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCertSignature(signed); err != nil {
		t.Fatal(err)
	}
	if signed.Pubkey != DevMockIssuerPubkeyHex() {
		t.Fatalf("pubkey=%q", signed.Pubkey)
	}
}

func TestRequestCommitmentHTTP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.gguf")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitment, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/attest-model" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		cert := NewCert(commitment, "m", "aabb", "nexqloud-model-attest")
		signed, err := SignCert(cert, DevMockIssuerPriv)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		m, err := signed.ToMap()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m)
	}))
	defer srv.Close()

	t.Setenv("NEXQLOUD_MODEL_ATTEST_URL", srv.URL)
	t.Setenv("NEXQLOUD_DEV", "")
	c, certMap, err := RequestCommitment("aabb")
	if err != nil {
		t.Fatal(err)
	}
	if c != commitment {
		t.Fatalf("commitment=%q want %q", c, commitment)
	}
	if certMap["nonce"] != "aabb" {
		t.Fatalf("cert=%#v", certMap)
	}
}

func TestRequestCommitmentRequiresURLOutsideDev(t *testing.T) {
	t.Setenv("NEXQLOUD_MODEL_ATTEST_URL", "")
	t.Setenv("NEXQLOUD_DEV", "0")
	if _, _, err := RequestCommitment("n"); err == nil {
		t.Fatal("expected error without attest URL")
	}
}

func TestRequestCommitmentDevMock(t *testing.T) {
	t.Setenv("NEXQLOUD_MODEL_ATTEST_URL", "")
	t.Setenv("NEXQLOUD_DEV", "1")
	t.Setenv("NEXQLOUD_MODEL_COMMIT", "sha256:deadbeef")
	c, certMap, err := RequestCommitment("nn")
	if err != nil {
		t.Fatal(err)
	}
	if c != "sha256:deadbeef" {
		t.Fatalf("got %q", c)
	}
	cert, err := CertFromMap(certMap)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCertSignature(cert); err != nil {
		t.Fatal(err)
	}
}
