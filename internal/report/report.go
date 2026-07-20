// Package report defines magpie's top-level scan result: the structure
// every renderer (terminal, JSON, markdown, CSV) draws from.
package report

import (
	"sort"
	"time"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/infer"
	"github.com/harborproject/magpie/internal/scan"
)

// SchemaVersion is the stable version of the JSON report schema. Bump it
// only on breaking changes to the JSON shape.
const SchemaVersion = 1

// PathResult is one documented well-known path's fetch outcome, trimmed to
// what every renderer needs (the full response body lives only in the
// scan.Result used to build the report, not in the report itself).
type PathResult struct {
	Path              string        `json:"path"`
	URL               string        `json:"url"`
	Presence          scan.Presence `json:"presence"`
	StatusCode        int           `json:"status_code,omitempty"`
	ContentType       string        `json:"content_type,omitempty"`
	Server            string        `json:"server,omitempty"`
	RedirectOffsiteTo string        `json:"redirect_offsite_to,omitempty"`
	TTFB              time.Duration `json:"ttfb_ms"`
	Total             time.Duration `json:"total_ms"`
}

// Report is the complete result of scanning one domain.
type Report struct {
	SchemaVersion int               `json:"schema_version"`
	Domain        string            `json:"domain"`
	ScannedAt     time.Time         `json:"scanned_at"`
	Control       scan.Control      `json:"control"`
	Paths         []PathResult      `json:"paths"`
	Findings      []finding.Finding `json:"findings"`
	Inference     infer.Result      `json:"inference"`
}

// Build assembles a Report from raw scan results and already-computed
// findings/inference, sorting paths and findings deterministically.
func Build(domain string, scannedAt time.Time, results []scan.Result, ctrl scan.Control, findings []finding.Finding, inference infer.Result) Report {
	paths := make([]PathResult, 0, len(results))
	for _, r := range results {
		paths = append(paths, PathResult{
			Path:              r.Path,
			URL:               r.URL,
			Presence:          r.Presence,
			StatusCode:        r.StatusCode,
			ContentType:       r.ContentType,
			Server:            r.Server,
			RedirectOffsiteTo: r.RedirectOffsiteTo,
			TTFB:              r.TTFB,
			Total:             r.Total,
		})
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].Path < paths[j].Path })

	sorted := append([]finding.Finding(nil), findings...)
	finding.Sort(sorted)

	return Report{
		SchemaVersion: SchemaVersion,
		Domain:        domain,
		ScannedAt:     scannedAt,
		Control:       ctrl,
		Paths:         paths,
		Findings:      sorted,
		Inference:     inference,
	}
}

// PresentPaths returns only the paths determined to be genuinely present.
func (r Report) PresentPaths() []PathResult {
	var out []PathResult
	for _, p := range r.Paths {
		if p.Presence == scan.PresencePresent {
			out = append(out, p)
		}
	}
	return out
}

// CountBySeverity returns the number of findings at each severity level.
func (r Report) CountBySeverity() map[finding.Severity]int {
	counts := map[finding.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}
