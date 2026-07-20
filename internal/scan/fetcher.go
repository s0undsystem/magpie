// Package scan implements magpie's passive HTTP fetch layer: one GET per
// documented well-known path, bounded concurrency, a token-bucket rate
// limiter, redirect tracking capped at five hops, and soft-404 detection via
// a control-path baseline.
package scan

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/harborproject/magpie/internal/registry"
)

// Config controls fetcher behavior.
type Config struct {
	Concurrency  int           // parallel requests per host
	RatePerSec   float64       // token-bucket refill rate, requests/sec
	Timeout      time.Duration // per-request timeout
	MaxRedirects int
	UserAgent    string
}

// DefaultConfig returns magpie's documented defaults: 10 parallel requests
// per host, a matching 10 req/s rate limit, and a 10 second timeout.
func DefaultConfig(userAgent string) Config {
	return Config{
		Concurrency:  10,
		RatePerSec:   10,
		Timeout:      10 * time.Second,
		MaxRedirects: 5,
		UserAgent:    userAgent,
	}
}

func (c Config) withDefaults() Config {
	if c.Concurrency <= 0 {
		c.Concurrency = 10
	}
	if c.RatePerSec <= 0 {
		c.RatePerSec = float64(c.Concurrency)
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxRedirects <= 0 {
		c.MaxRedirects = 5
	}
	return c
}

// Result is the outcome of fetching a single documented well-known path.
type Result struct {
	Path          string // registry-relative path, e.g. "security.txt"
	URL           string // URL requested
	Entry         registry.Entry
	Presence      Presence
	StatusCode    int
	ContentType   string
	Body          []byte
	Headers       http.Header
	RedirectChain []string
	// RedirectOffsiteTo is the hostname a redirect chain left the original
	// host for, set only when Presence == PresenceRedirectedOffsite.
	RedirectOffsiteTo string
	TTFB               time.Duration
	Total              time.Duration
	Server             string
	Err                string
}

// Fetcher performs the passive, read-only well-known scan for a single
// host.
type Fetcher struct {
	cfg       Config
	transport *http.Transport
	limiter   *RateLimiter
}

// New creates a Fetcher. Zero-valued Config fields fall back to
// DefaultConfig's values.
func New(cfg Config) *Fetcher {
	cfg = cfg.withDefaults()
	return &Fetcher{
		cfg: cfg,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		limiter: NewRateLimiter(cfg.RatePerSec, cfg.Concurrency),
	}
}

// Scan fetches the soft-404 control probe, then every entry in entries,
// against baseURL (e.g. "https://example.org"). Results are returned sorted
// by path for deterministic output regardless of completion order.
func (f *Fetcher) Scan(ctx context.Context, baseURL string, entries []registry.Entry) ([]Result, Control, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, Control{}, fmt.Errorf("scan: invalid base URL %q: %w", baseURL, err)
	}

	controlPath := "/.well-known/" + ControlToken(nil)
	controlRaw := f.fetchOne(ctx, base, controlPath)
	ctrl := newControl(controlRaw)

	sorted := make([]registry.Entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	results := make([]Result, len(sorted))
	sem := make(chan struct{}, f.cfg.Concurrency)
	var wg sync.WaitGroup
	for i, e := range sorted {
		wg.Add(1)
		go func(i int, e registry.Entry) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = Result{Path: e.Path, URL: base.String() + e.FullPath(), Entry: e, Presence: PresenceError, Err: ctx.Err().Error()}
				return
			}
			defer func() { <-sem }()

			if err := f.limiter.Wait(ctx); err != nil {
				results[i] = Result{Path: e.Path, URL: base.String() + e.FullPath(), Entry: e, Presence: PresenceError, Err: err.Error()}
				return
			}
			raw := f.fetchOne(ctx, base, e.FullPath())
			results[i] = f.classify(e, base, raw, ctrl)
		}(i, e)
	}
	wg.Wait()

	return results, ctrl, nil
}

// rawResponse is the unclassified outcome of a single GET.
type rawResponse struct {
	StatusCode    int
	ContentType   string
	Body          []byte
	Headers       http.Header
	RedirectChain []string
	OffsiteHost   string
	TTFB          time.Duration
	Total         time.Duration
	Err           error
}

// fetchOne issues exactly one logical GET (following same-host redirects up
// to MaxRedirects) for path against base.
func (f *Fetcher) fetchOne(ctx context.Context, base *url.URL, path string) *rawResponse {
	target := *base
	target.Path = path
	reqURL := target.String()

	originalHost := base.Host
	var redirectChain []string
	var offsiteHost string

	client := &http.Client{
		Transport: f.transport,
		Timeout:   f.cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirectChain = append(redirectChain, req.URL.String())
			if req.URL.Host != originalHost {
				offsiteHost = req.URL.Hostname()
				return http.ErrUseLastResponse
			}
			if len(via) >= f.cfg.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", f.cfg.MaxRedirects)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return &rawResponse{Err: err}
	}
	req.Header.Set("User-Agent", f.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	var ttfb time.Duration
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { ttfb = time.Since(start) },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)
	total := time.Since(start)
	if err != nil {
		return &rawResponse{Err: err, RedirectChain: redirectChain, OffsiteHost: offsiteHost, Total: total}
	}
	defer resp.Body.Close()

	const maxBody = 5 << 20 // 5MB cap; well-known documents are small text/JSON.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return &rawResponse{Err: err, StatusCode: resp.StatusCode, Total: total}
	}

	return &rawResponse{
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("Content-Type"),
		Body:          body,
		Headers:       resp.Header,
		RedirectChain: redirectChain,
		OffsiteHost:   offsiteHost,
		TTFB:          ttfb,
		Total:         total,
	}
}

// classify turns a raw response into a presence determination, applying the
// soft-404 control comparison and the kind-specific content checks.
func (f *Fetcher) classify(e registry.Entry, base *url.URL, raw *rawResponse, ctrl Control) Result {
	res := Result{
		Path:          e.Path,
		URL:           base.String() + e.FullPath(),
		Entry:         e,
		RedirectChain: raw.RedirectChain,
		TTFB:          raw.TTFB,
		Total:         raw.Total,
	}

	if raw.Err != nil {
		res.Presence = PresenceError
		res.Err = raw.Err.Error()
		return res
	}

	res.StatusCode = raw.StatusCode
	res.ContentType = raw.ContentType
	res.Body = raw.Body
	res.Headers = raw.Headers
	res.Server = DetectServer(raw.Headers)

	if raw.OffsiteHost != "" {
		res.Presence = PresenceRedirectedOffsite
		res.RedirectOffsiteTo = raw.OffsiteHost
		return res
	}

	if raw.StatusCode != http.StatusOK {
		res.Presence = PresenceAbsent
		return res
	}

	if resemblesControl(raw, ctrl) {
		res.Presence = PresenceSoft404
		return res
	}

	switch e.Kind {
	case "json":
		if strings.Contains(strings.ToLower(baseContentType(raw.ContentType)), "html") {
			res.Presence = PresenceSoft404
			return res
		}
		if !json.Valid(raw.Body) {
			res.Presence = PresenceSoft404
			return res
		}
	case "text":
		lower := strings.ToLower(string(raw.Body))
		if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") {
			res.Presence = PresenceSoft404
			return res
		}
	}

	res.Presence = PresencePresent
	return res
}
