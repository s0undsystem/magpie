package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/s0undsystem/magpie/internal/snapshot"
)

func TestPostWebhookSendsJSON(t *testing.T) {
	var received snapshot.Diff
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decoding request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := snapshot.Diff{Domain: "example.org", PathsAppeared: []string{"security.txt"}}
	if err := postWebhook(t.Context(), srv.URL, d); err != nil {
		t.Fatal(err)
	}
	if received.Domain != "example.org" {
		t.Errorf("received.Domain = %q", received.Domain)
	}
	if len(received.PathsAppeared) != 1 || received.PathsAppeared[0] != "security.txt" {
		t.Errorf("received.PathsAppeared = %v", received.PathsAppeared)
	}
}

func TestPostWebhookNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := postWebhook(t.Context(), srv.URL, snapshot.Diff{}); err == nil {
		t.Error("expected an error for a non-2xx webhook response")
	}
}

func TestPostWebhookUnreachable(t *testing.T) {
	if err := postWebhook(t.Context(), "http://127.0.0.1:1/nope", snapshot.Diff{}); err == nil {
		t.Error("expected an error for an unreachable webhook URL")
	}
}
