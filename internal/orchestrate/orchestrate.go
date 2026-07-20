// Package orchestrate wires together the fetch, validate, correlate, and
// infer layers into a single scan of one domain.
package orchestrate

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/harborproject/magpie/internal/correlate"
	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/infer"
	"github.com/harborproject/magpie/internal/registry"
	"github.com/harborproject/magpie/internal/report"
	"github.com/harborproject/magpie/internal/scan"
	"github.com/harborproject/magpie/internal/validate"
)

// Options controls one scan run.
type Options struct {
	Concurrency  int
	RatePerSec   float64
	Timeout      time.Duration
	UserAgent    string
	MaxRedirects int

	// RulesOverlay is optional additional/overriding correlation rules
	// JSON, as loaded from --rules.
	RulesOverlay []byte

	// DisableAuxFetch skips the single auxiliary GET security.txt's
	// validator uses to verify a PGP key referenced by Encryption.
	DisableAuxFetch bool
	// DisableDNS skips the DNS TXT/MX lookups mta-sts.txt cross-checks use.
	DisableDNS bool
}

// Run performs one full scan of host and returns the assembled report.
func Run(ctx context.Context, host string, opts Options) (report.Report, error) {
	reg, err := registry.Load()
	if err != nil {
		return report.Report{}, err
	}

	fetcher := scan.New(scan.Config{
		Concurrency:  opts.Concurrency,
		RatePerSec:   opts.RatePerSec,
		Timeout:      opts.Timeout,
		MaxRedirects: opts.MaxRedirects,
		UserAgent:    opts.UserAgent,
	})

	scannedAt := time.Now().UTC()
	results, ctrl, err := fetcher.Scan(ctx, "https://"+host, reg.Entries)
	if err != nil {
		return report.Report{}, err
	}

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	outputs := make(map[string]validate.Output, len(results))
	for _, r := range results {
		v, ok := validate.Lookup(r.Path)
		if !ok {
			continue
		}
		vctx := validate.Context{Host: host, Result: r}
		if !opts.DisableAuxFetch {
			vctx.Fetch = auxFetcher(ctx, client, opts.UserAgent)
		}
		if !opts.DisableDNS {
			vctx.LookupTXT = func(name string) ([]string, error) {
				return net.DefaultResolver.LookupTXT(ctx, name)
			}
		}
		outputs[r.Path] = v.Validate(vctx)
	}

	snap := correlate.BuildSnapshot(host, results, outputs)

	engine := correlate.NewEngine()
	if len(opts.RulesOverlay) > 0 {
		if err := engine.LoadOverlay(opts.RulesOverlay); err != nil {
			return report.Report{}, err
		}
	}

	evalOpts := correlate.EvalOptions{}
	if !opts.DisableDNS {
		evalOpts.LookupMX = func(h string) ([]string, error) {
			mxs, err := net.DefaultResolver.LookupMX(ctx, h)
			if err != nil {
				return nil, err
			}
			hosts := make([]string, len(mxs))
			for i, mx := range mxs {
				hosts[i] = mx.Host
			}
			return hosts, nil
		}
	}

	var findings []finding.Finding
	for _, out := range outputs {
		findings = append(findings, out.Findings...)
	}
	findings = append(findings, engine.Evaluate(snap, evalOpts)...)

	inference := infer.Infer(snap)

	return report.Build(host, scannedAt, results, ctrl, findings, inference), nil
}

// auxFetcher returns a validate.AuxFetcher performing exactly one GET
// against an explicitly referenced URL pulled from already-fetched
// content (e.g. security.txt's Encryption field), never a guessed path.
func auxFetcher(ctx context.Context, client *http.Client, userAgent string) validate.AuxFetcher {
	return func(target string) (*scan.Result, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := client.Do(req)
		if err != nil {
			return &scan.Result{URL: target, Presence: scan.PresenceError, Err: err.Error()}, nil
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return &scan.Result{URL: target, Presence: scan.PresenceError, Err: err.Error()}, nil
		}

		presence := scan.PresenceAbsent
		if resp.StatusCode == http.StatusOK {
			presence = scan.PresencePresent
		}
		return &scan.Result{
			URL:         target,
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Body:        body,
			Presence:    presence,
		}, nil
	}
}
