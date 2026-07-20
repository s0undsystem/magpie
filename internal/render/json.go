package render

import (
	"encoding/json"
	"io"
	"time"

	"github.com/harborproject/magpie/internal/report"
)

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

func JSON(w io.Writer, rep report.Report, opts Options) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(prepareForJSON(rep, opts))
}

func JSONLine(w io.Writer, rep report.Report, opts Options) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(prepareForJSON(rep, opts))
}
