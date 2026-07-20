// Package ct expands a scan to subdomains discovered via public
// certificate transparency logs (crt.sh). This is passive: it queries a
// public log aggregator for certificates already issued for the domain and
// reads the hostnames those certificates list. It performs no DNS brute
// forcing, wordlist enumeration, or probing of any kind — every hostname it
// returns is one a certificate authority has already publicly logged.
package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// DefaultLimit is the default cap on subdomains returned, matching --ct-limit's default.
const DefaultLimit = 50

// baseURL is overridable in tests.
var baseURL = "https://crt.sh/"

// Result is the outcome of a certificate transparency lookup.
type Result struct {
	Subdomains []string // sorted, deduplicated, capped at limit
	Truncated  bool     // true if more subdomains were found than limit allowed
}

type crtSHEntry struct {
	NameValue string `json:"name_value"`
}

// Lookup queries crt.sh for certificates covering *.domain and returns the
// distinct subdomains found in their Subject Alternative Names, sorted and
// capped at limit (DefaultLimit if limit <= 0).
func Lookup(ctx context.Context, client *http.Client, domain string, limit int) (Result, error) {
	if limit <= 0 {
		limit = DefaultLimit
	}

	q := url.Values{}
	q.Set("q", "%."+domain)
	q.Set("output", "json")
	reqURL := baseURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("ct: querying crt.sh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("ct: crt.sh returned status %d", resp.StatusCode)
	}

	var entries []crtSHEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return Result{}, fmt.Errorf("ct: parsing crt.sh response: %w", err)
	}

	domain = strings.ToLower(domain)
	suffix := "." + domain
	set := map[string]bool{}
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			h := strings.ToLower(strings.TrimSpace(line))
			h = strings.TrimPrefix(h, "*.")
			if h == "" || h == domain || !strings.HasSuffix(h, suffix) {
				continue
			}
			set[h] = true
		}
	}

	subs := make([]string, 0, len(set))
	for h := range set {
		subs = append(subs, h)
	}
	sort.Strings(subs)

	truncated := false
	if len(subs) > limit {
		subs = subs[:limit]
		truncated = true
	}

	return Result{Subdomains: subs, Truncated: truncated}, nil
}
