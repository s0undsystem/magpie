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

	"github.com/s0undsystem/magpie/internal/registry"
)

type Config struct {
	Concurrency  int
	RatePerSec   float64
	Timeout      time.Duration
	MaxRedirects int
	UserAgent    string
}

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

type Result struct {
	Path          string
	URL           string
	Entry         registry.Entry
	Presence      Presence
	StatusCode    int
	ContentType   string
	Body          []byte
	Headers       http.Header
	RedirectChain []string

	RedirectOffsiteTo string
	TTFB              time.Duration
	Total             time.Duration
	Server            string
	Err               string
}

type Fetcher struct {
	cfg       Config
	transport *http.Transport
	limiter   *RateLimiter
}

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

	const maxBody = 5 << 20
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
