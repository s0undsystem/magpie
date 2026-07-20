package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harborproject/magpie/internal/registry"
)

func testEntries() []registry.Entry {
	return []registry.Entry{
		{Path: "security.txt", Kind: "text", ContentType: "text/plain"},
		{Path: "openid-configuration", Kind: "json", ContentType: "application/json"},
		{Path: "assetlinks.json", Kind: "json", ContentType: "application/json"},
		{Path: "change-password", Kind: "html", ContentType: "text/html"},
	}
}

func fastConfig(userAgent string) Config {
	cfg := DefaultConfig(userAgent)
	cfg.Timeout = 3 * time.Second
	cfg.RatePerSec = 1000
	return cfg
}

func TestPresentAndAbsent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Contact: mailto:security@example.org\nExpires: 2030-01-01T00:00:00Z\n"))
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"https://example.org"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := New(fastConfig("magpie-test/1.0"))
	results, ctrl, err := f.Scan(context.Background(), srv.URL, testEntries())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if ctrl.StatusCode != 404 {
		t.Errorf("control StatusCode = %d, want 404", ctrl.StatusCode)
	}

	byPath := map[string]Result{}
	for _, r := range results {
		byPath[r.Path] = r
	}

	if got := byPath["security.txt"].Presence; got != PresencePresent {
		t.Errorf("security.txt presence = %q, want present", got)
	}
	if got := byPath["openid-configuration"].Presence; got != PresencePresent {
		t.Errorf("openid-configuration presence = %q, want present", got)
	}
	if got := byPath["assetlinks.json"].Presence; got != PresenceAbsent {
		t.Errorf("assetlinks.json presence = %q, want absent", got)
	}
	if got := byPath["change-password"].Presence; got != PresenceAbsent {
		t.Errorf("change-password presence = %q, want absent", got)
	}
}

func TestSoft404Detection(t *testing.T) {
	softBody := `<!DOCTYPE html><html><head><title>Oops</title></head><body>` +
		strings.Repeat("We could not find that page. ", 20) + `</body></html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(softBody))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := New(fastConfig("magpie-test/1.0"))
	results, ctrl, err := f.Scan(context.Background(), srv.URL, testEntries())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if ctrl.StatusCode != 200 {
		t.Fatalf("control StatusCode = %d, want 200 (soft-404 host)", ctrl.StatusCode)
	}

	for _, r := range results {
		if r.Presence != PresenceSoft404 {
			t.Errorf("path %s presence = %q, want soft404 (naive status-code check would false-positive here)", r.Path, r.Presence)
		}
	}
}

func TestJSONKindRejectsHTMLDespiteDifferingFromControl(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Custom unrelated per-path HTML content that differs from the control page entirely and is much longer than the control body so hash and length comparisons alone would not catch it as a soft 404 case here.</body></html>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("nope"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := New(fastConfig("magpie-test/1.0"))
	results, _, err := f.Scan(context.Background(), srv.URL, testEntries())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, r := range results {
		if r.Path == "openid-configuration" {
			if r.Presence != PresenceSoft404 {
				t.Errorf("openid-configuration presence = %q, want soft404 (HTML content-type for a JSON-required path)", r.Presence)
			}
			return
		}
	}
	t.Fatal("openid-configuration result not found")
}

func TestTextKindRejectsEmbeddedHTML(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html>this host serves an SPA shell for every route including this one and it is long enough to not match the control by length</html>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("short"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := New(fastConfig("magpie-test/1.0"))
	results, _, err := f.Scan(context.Background(), srv.URL, testEntries())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, r := range results {
		if r.Path == "security.txt" {
			if r.Presence != PresenceSoft404 {
				t.Errorf("security.txt presence = %q, want soft404 (embedded <!DOCTYPE html>)", r.Presence)
			}
			return
		}
	}
	t.Fatal("security.txt result not found")
}

func TestRedirectOffsite(t *testing.T) {
	var offsiteHits int
	offsite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offsiteHits++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not be fetched"))
	}))
	defer offsite.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/change-password", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, offsite.URL+"/account/password", http.StatusFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := New(fastConfig("magpie-test/1.0"))
	results, _, err := f.Scan(context.Background(), srv.URL, testEntries())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, r := range results {
		if r.Path == "change-password" {
			if r.Presence != PresenceRedirectedOffsite {
				t.Errorf("change-password presence = %q, want redirected-offsite", r.Presence)
			}
			offsiteHost, err := url.Parse(offsite.URL)
			if err != nil {
				t.Fatal(err)
			}
			if r.RedirectOffsiteTo != offsiteHost.Hostname() {
				t.Errorf("RedirectOffsiteTo = %q, want %q", r.RedirectOffsiteTo, offsiteHost.Hostname())
			}
			if offsiteHits != 0 {
				t.Errorf("offsite host was fetched %d times, want 0 (magpie must not follow off-host redirects)", offsiteHits)
			}
			return
		}
	}
	t.Fatal("change-password result not found")
}

func TestRedirectSameHostFollowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/change-password", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/account/password", http.StatusFound)
	})
	mux.HandleFunc("/account/password", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Change your password</body></html>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := New(fastConfig("magpie-test/1.0"))
	results, _, err := f.Scan(context.Background(), srv.URL, testEntries())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, r := range results {
		if r.Path == "change-password" {
			if r.Presence != PresencePresent {
				t.Errorf("change-password presence = %q, want present", r.Presence)
			}
			if len(r.RedirectChain) == 0 {
				t.Error("expected a recorded same-host redirect hop")
			}
			return
		}
	}
	t.Fatal("change-password result not found")
}

func TestTooManyRedirectsIsError(t *testing.T) {
	mux := http.NewServeMux()
	for i := 0; i < 8; i++ {
		i := i
		mux.HandleFunc("/hop"+itoa(i), func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/hop"+itoa(i+1), http.StatusFound)
		})
	}
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/hop0", http.StatusFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := New(fastConfig("magpie-test/1.0"))
	results, _, err := f.Scan(context.Background(), srv.URL, testEntries())
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	for _, r := range results {
		if r.Path == "security.txt" {
			if r.Presence != PresenceError {
				t.Errorf("security.txt presence = %q, want error (too many redirects)", r.Presence)
			}
			return
		}
	}
	t.Fatal("security.txt result not found")
}

func TestUserAgentSent(t *testing.T) {
	var gotUA string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.Write([]byte("Contact: mailto:security@example.org"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ua := "magpie/1.2.3 (+https://github.com/harborproject/magpie)"
	f := New(fastConfig(ua))
	if _, _, err := f.Scan(context.Background(), srv.URL, testEntries()); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if gotUA != ua {
		t.Errorf("User-Agent = %q, want %q", gotUA, ua)
	}
}

func TestSingleGETPerPath(t *testing.T) {
	var mu countingMux
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.inc()
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := New(fastConfig("magpie-test/1.0"))
	entries := testEntries()
	if _, _, err := f.Scan(context.Background(), srv.URL, entries); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	want := len(entries) + 1
	if got := mu.count(); got != want {
		t.Errorf("total requests = %d, want %d (one per documented path plus one control)", got, want)
	}
}

func TestScanIsDeterministic(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Contact: mailto:security@example.org\nExpires: 2030-01-01T00:00:00Z\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := New(fastConfig("magpie-test/1.0"))
	entries := testEntries()

	r1, _, err := f.Scan(context.Background(), srv.URL, entries)
	if err != nil {
		t.Fatal(err)
	}
	r2, _, err := f.Scan(context.Background(), srv.URL, entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(r1) != len(r2) {
		t.Fatalf("result count differs: %d vs %d", len(r1), len(r2))
	}
	for i := range r1 {
		if r1[i].Path != r2[i].Path {
			t.Fatalf("result order differs at %d: %s vs %s", i, r1[i].Path, r2[i].Path)
		}
		if r1[i].Presence != r2[i].Presence || string(r1[i].Body) != string(r2[i].Body) {
			t.Fatalf("result content differs at path %s", r1[i].Path)
		}
	}
}

type countingMux struct {
	n int64
}

func (c *countingMux) inc() { atomic.AddInt64(&c.n, 1) }
func (c *countingMux) count() int {
	return int(atomic.LoadInt64(&c.n))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
