package ct

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func withTestServer(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	oldBase := baseURL
	baseURL = srv.URL + "/"
	t.Cleanup(func() { baseURL = oldBase })
	return srv.Client()
}

func jsonHandler(entries []crtSHEntry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}
}

func TestLookupDedupesAndSorts(t *testing.T) {
	client := withTestServer(t, jsonHandler([]crtSHEntry{
		{NameValue: "www.example.org\nmail.example.org"},
		{NameValue: "mail.example.org"}, // duplicate
		{NameValue: "*.api.example.org"},
	}))

	res, err := Lookup(context.Background(), client, "example.org", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.org", "mail.example.org", "www.example.org"}
	if len(res.Subdomains) != len(want) {
		t.Fatalf("got %v, want %v", res.Subdomains, want)
	}
	for i := range want {
		if res.Subdomains[i] != want[i] {
			t.Errorf("Subdomains[%d] = %q, want %q", i, res.Subdomains[i], want[i])
		}
	}
	if res.Truncated {
		t.Error("did not expect truncation")
	}
}

func TestLookupExcludesBareDomainAndUnrelatedHosts(t *testing.T) {
	client := withTestServer(t, jsonHandler([]crtSHEntry{
		{NameValue: "example.org"},     // the bare domain itself, not a subdomain
		{NameValue: "example.net"},     // different domain entirely
		{NameValue: "notexample.org"},  // similar suffix but not a subdomain
		{NameValue: "sub.example.org"}, // genuine subdomain
	}))

	res, err := Lookup(context.Background(), client, "example.org", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Subdomains) != 1 || res.Subdomains[0] != "sub.example.org" {
		t.Errorf("Subdomains = %v, want [sub.example.org]", res.Subdomains)
	}
}

func TestLookupRespectsLimit(t *testing.T) {
	client := withTestServer(t, jsonHandler([]crtSHEntry{
		{NameValue: "a.example.org\nb.example.org\nc.example.org"},
	}))

	res, err := Lookup(context.Background(), client, "example.org", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Subdomains) != 2 {
		t.Fatalf("got %d subdomains, want 2", len(res.Subdomains))
	}
	if !res.Truncated {
		t.Error("expected Truncated = true when results exceed the limit")
	}
}

func TestLookupDefaultLimitAppliesWhenZero(t *testing.T) {
	var entries []crtSHEntry
	names := ""
	for i := 0; i < DefaultLimit+10; i++ {
		names += string(rune('a'+i%26)) + string(rune('0'+i%10)) + ".example.org\n"
	}
	entries = append(entries, crtSHEntry{NameValue: names})
	client := withTestServer(t, jsonHandler(entries))

	res, err := Lookup(context.Background(), client, "example.org", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Subdomains) != DefaultLimit {
		t.Errorf("got %d subdomains, want default limit %d", len(res.Subdomains), DefaultLimit)
	}
}

func TestLookupNonOKStatus(t *testing.T) {
	client := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	if _, err := Lookup(context.Background(), client, "example.org", 0); err == nil {
		t.Error("expected an error for a non-200 response")
	}
}

func TestLookupInvalidJSON(t *testing.T) {
	client := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	})
	if _, err := Lookup(context.Background(), client, "example.org", 0); err == nil {
		t.Error("expected an error for an invalid JSON response")
	}
}

func TestLookupEmptyResults(t *testing.T) {
	client := withTestServer(t, jsonHandler(nil))
	res, err := Lookup(context.Background(), client, "example.org", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Subdomains) != 0 {
		t.Errorf("expected no subdomains, got %v", res.Subdomains)
	}
}
