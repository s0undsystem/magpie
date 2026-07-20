package render

import (
	"encoding/json"
	"io"
	"time"

	"github.com/harborproject/magpie/internal/report"
)

// JSON writes the complete structured report to w, applying opts.Filter to
// the findings list. Field order is fixed by struct definition order, and
// slices are already sorted by report.Build, so two renders of unchanged
// input produce byte-identical output apart from scanned_at and timing
// fields (suppressible via opts.NoTimestamps).
func JSON(w io.Writer, rep report.Report, opts Options) error {
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

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
