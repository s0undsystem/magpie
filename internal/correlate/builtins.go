package correlate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
)

// registerBuiltins wires up the handful of rules whose logic genuinely
// can't be expressed as a static Condition tree: iterating over a variable
// number of documents (CORR-007), a live DNS lookup plus wildcard pattern
// matching (CORR-022), and a generic cross-document fact-map comparison
// (CORR-024). Every other rule lives entirely in rules.json.
func registerBuiltins(e *Engine) {
	e.RegisterBuiltin("corr007_offsite_redirects", corr007OffsiteRedirects)
	e.RegisterBuiltin("corr022_mx_mismatch", corr022MXMismatch)
	e.RegisterBuiltin("corr024_generic_disagreement", corr024GenericDisagreement)
}

func sortedPaths(snap Snapshot) []string {
	paths := make([]string, 0, len(snap.Docs))
	for p := range snap.Docs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// corr007OffsiteRedirects emits one finding per well-known path whose
// redirect chain left the original host.
func corr007OffsiteRedirects(snap Snapshot, rule Rule, _ EvalOptions) []finding.Finding {
	var out []finding.Finding
	for _, path := range sortedPaths(snap) {
		d := snap.Docs[path]
		if d.Presence != scan.PresenceRedirectedOffsite {
			continue
		}
		out = append(out, finding.Finding{
			ID: rule.ID, Severity: rule.Severity, Confidence: rule.Confidence, Category: rule.Category,
			Message:  rule.Message,
			Evidence: fmt.Sprintf("/.well-known/%s redirected to %s", path, d.RedirectOffsiteTo),
			SpecRef:  rule.SpecRef,
		})
	}
	return out
}

// corr022MXMismatch checks whether every MX host actually serving mail for
// the domain is covered by an mx pattern in mta-sts.txt. It requires a live
// DNS MX lookup, supplied via opts.LookupMX; when that's unavailable the
// rule simply doesn't fire.
func corr022MXMismatch(snap Snapshot, rule Rule, opts EvalOptions) []finding.Finding {
	if opts.LookupMX == nil {
		return nil
	}
	d, ok := snap.Docs["mta-sts.txt"]
	if !ok || d.Presence != scan.PresencePresent {
		return nil
	}
	patternsRaw, ok := d.Facts["mx_patterns"]
	if !ok || patternsRaw == "" {
		return nil
	}
	patterns := strings.Split(patternsRaw, ",")

	actual, err := opts.LookupMX(snap.Host)
	if err != nil || len(actual) == 0 {
		return nil
	}
	sort.Strings(actual)

	var uncovered []string
	for _, mx := range actual {
		if !matchesAnyMXPattern(mx, patterns) {
			uncovered = append(uncovered, mx)
		}
	}
	if len(uncovered) == 0 {
		return nil
	}

	return []finding.Finding{{
		ID: rule.ID, Severity: rule.Severity, Confidence: rule.Confidence, Category: rule.Category,
		Message:  rule.Message,
		Evidence: fmt.Sprintf("MX host(s) not covered by any mx pattern (%s): %s", patternsRaw, strings.Join(uncovered, ", ")),
		SpecRef:  rule.SpecRef,
	}}
}

func matchesAnyMXPattern(mx string, patterns []string) bool {
	mx = strings.ToLower(strings.TrimSuffix(mx, "."))
	for _, raw := range patterns {
		p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".example.com"
			if strings.HasSuffix(mx, suffix) && mx != suffix[1:] {
				return true
			}
			continue
		}
		if mx == p {
			return true
		}
	}
	return false
}

// comparableFactKeys are logical facts the generic disagreement scanner
// compares across documents. "issuer" is intentionally excluded for the
// (openid-configuration, oauth-authorization-server) pair, since CORR-020
// already owns that specific comparison; the exclusion keeps this rule
// focused on conflicts "not anticipated by a specific rule," per its
// purpose. New validators can opt into this check simply by emitting a fact
// under one of these keys — no code change required here.
var comparableFactKeys = []string{"issuer", "organization_name", "app_identity", "contact_domain"}

// corr024GenericDisagreement scans every document's facts for shared
// logical-fact keys and flags any pair of documents that assert different
// non-empty values for the same key.
func corr024GenericDisagreement(snap Snapshot, rule Rule, _ EvalOptions) []finding.Finding {
	var out []finding.Finding
	paths := sortedPaths(snap)

	for _, key := range comparableFactKeys {
		type seenVal struct{ path, value string }
		var seen []seenVal
		for _, p := range paths {
			if key == "issuer" && (p == "openid-configuration" || p == "oauth-authorization-server") {
				continue
			}
			v, ok := snap.Docs[p].Facts[key]
			if !ok || v == "" {
				continue
			}
			seen = append(seen, seenVal{p, v})
		}
		for i := 0; i < len(seen); i++ {
			for j := i + 1; j < len(seen); j++ {
				if seen[i].value == seen[j].value {
					continue
				}
				out = append(out, finding.Finding{
					ID: rule.ID, Severity: rule.Severity, Confidence: rule.Confidence, Category: rule.Category,
					Message: rule.Message,
					Evidence: fmt.Sprintf("%s: %s=%q vs %s=%q", key,
						seen[i].path, seen[i].value, seen[j].path, seen[j].value),
					SpecRef: rule.SpecRef,
				})
			}
		}
	}
	return out
}
