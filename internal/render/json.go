package render

import (
	"encoding/json"
	"io"
	"time"

	"github.com/harborproject/magpie/internal/report"
)

// prepareForJSON applies opts.Filter to the findings list and, when
// opts.NoTimestamps is set, zeroes ScannedAt and per-path timing, without
// mutating rep.
func prepareForJSON(rep report.Report, opts Options) report.Report {
	out := rep
	out.Findings = opts.Filter.Apply(rep.Findings)
	if opts.NoTimestamps {
		out.ScannedAt = time.Time{}
		out.Paths = append([]report.PathResult(nil), rep.Paths...)
		for i := range out.Paths {
			out.Paths[i].TTFB = 0
			out.Paths[i].Total = 0
		}
	}
	return out
}

// JSON writes the complete structured report to w, applying opts.Filter to
// the findings list. Field order is fixed by struct definition order, and
// slices are already sorted by report.Build, so two renders of unchanged
// input produce byte-identical output apart from scanned_at and timing
// fields (suppressible via opts.NoTimestamps).
func JSON(w io.Writer, rep report.Report, opts Options) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(prepareForJSON(rep, opts))
}

// JSONLine writes rep as a single compact JSON line (no indentation),
// suitable for newline-delimited output piped to jq in batch mode.
func JSONLine(w io.Writer, rep report.Report, opts Options) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(prepareForJSON(rep, opts))
}
