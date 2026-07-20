package correlate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/s0undsystem/magpie/internal/finding"
	"github.com/s0undsystem/magpie/internal/scan"
)

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
			suffix := p[1:]
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

var comparableFactKeys = []string{"issuer", "organization_name", "app_identity", "contact_domain"}

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
