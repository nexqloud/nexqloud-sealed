package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The ledger is reached through a public route, so the publish carries the credential that route
// is gated by. These tests pin the two halves that matter to whoever owns that route: the header
// it can check, and the body it can read.

// aLedger stands in for the ledger route and hands back the one request it was sent.
func aLedger(t *testing.T) (*httptest.Server, chan *http.Request, chan []byte) {
	t.Helper()
	requests := make(chan *http.Request, 4)
	bodies := make(chan []byte, 4)
	ledger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- r.Clone(r.Context())
		bodies <- body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ledger.Close)
	return ledger, requests, bodies
}

// theShimThatPublishes is a shim with only what a publish needs, pointed at one ledger.
func theShimThatPublishes(url, token, verifyMode string) *server {
	return &server{
		ledgerURL:   url,
		ledgerToken: token,
		endpointKey: "endpoint-1",
		verifyMode:  verifyMode,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
}

// waited reads from a channel the publish fills, or says plainly that nothing arrived.
func waited(t *testing.T, what <-chan *http.Request) *http.Request {
	t.Helper()
	select {
	case request := <-what:
		return request
	case <-time.After(3 * time.Second):
		t.Fatalf("no %s arrived", "publish")
		return nil
	}
}

func TestTheReceiptPublishCarriesTheTokenTheLedgerRouteChecks(t *testing.T) {
	ledger, requests, bodies := aLedger(t)
	shim := theShimThatPublishes(ledger.URL, "a-shared-secret", "per-response")

	shim.publishReceipt(map[string]any{"package": map[string]any{"receipt_id": "receipt-1"}})

	request := waited(t, requests)
	if got, want := request.Header.Get("Authorization"), "Bearer a-shared-secret"; got != want {
		t.Errorf("the ledger would check %q, but the publish carried %q", want, got)
	}
	if got := request.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type is %q; the route reads json", got)
	}
	var sent struct {
		EndpointKey string         `json:"endpointKey"`
		Receipt     map[string]any `json:"receipt"`
	}
	if err := json.Unmarshal(<-bodies, &sent); err != nil {
		t.Fatalf("the publish body is not the json the route expects: %v", err)
	}
	if sent.EndpointKey != "endpoint-1" {
		t.Errorf("the publish named endpoint %q, not the shim's own key", sent.EndpointKey)
	}
	if sent.Receipt == nil {
		t.Error("the publish carried no receipt")
	}
}

func TestAPublishWithoutATokenCarriesNoCredential(t *testing.T) {
	// A ledger reached over a private path needs none; what must not happen is a shim
	// inventing a header (an empty bearer) that a route would then have to special-case.
	ledger, requests, _ := aLedger(t)
	shim := theShimThatPublishes(ledger.URL, "", "per-response")

	shim.publishReceipt(map[string]any{"package": map[string]any{"receipt_id": "receipt-1"}})

	if got := waited(t, requests).Header.Get("Authorization"); got != "" {
		t.Errorf("an unconfigured token still sent %q", got)
	}
}

func TestNothingIsPublishedWithoutALedger(t *testing.T) {
	// Nothing to publish to means nothing is sent — and above all, no attempt is made
	// against an empty URL, which would fail as "unsupported protocol scheme".
	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })

	shim := theShimThatPublishes("", "a-shared-secret", "per-response")
	shim.publishReceipt(map[string]any{"package": map[string]any{"receipt_id": "receipt-1"}})

	time.Sleep(250 * time.Millisecond)
	if strings.Contains(logged.String(), "ledger:") {
		t.Errorf("an unconfigured ledger still produced a publish attempt: %s", logged.String())
	}
}

func TestNothingIsPublishedWhenVerificationIsOff(t *testing.T) {
	// Off means no receipt exists to publish, so the ledger is left alone.
	ledger, requests, _ := aLedger(t)
	shim := theShimThatPublishes(ledger.URL, "a-shared-secret", "off")

	shim.publishReceipt(map[string]any{"package": map[string]any{"receipt_id": "receipt-1"}})

	select {
	case request := <-requests:
		t.Errorf("a publish went out where none was due: %s", request.URL)
	case <-time.After(250 * time.Millisecond):
	}
}

func TestARefusedPublishIsNotRetried(t *testing.T) {
	// The ledger's own answer is the last word: a 401 or a 500 is logged and dropped, not
	// hammered at. Whoever owns the route has to be able to trust that a broken token does
	// not turn every answer into a retry loop.
	var attempts int
	ledger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(ledger.Close)
	shim := theShimThatPublishes(ledger.URL, "a-wrong-secret", "per-response")

	shim.publishReceipt(map[string]any{"package": map[string]any{"receipt_id": "receipt-1"}})

	time.Sleep(500 * time.Millisecond)
	if attempts != 1 {
		t.Errorf("a refused publish was sent %d times; it should be sent once", attempts)
	}
}
