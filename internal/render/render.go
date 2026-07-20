// Package render turns a report.Report into terminal, JSON, markdown, or
// CSV output. Every renderer walks report.Paths and report.Findings in the
// order report.Build already sorted them, so two renders of unchanged input
// are byte-identical apart from timestamps and timing (both suppressible).
package render

import (
	"github.com/harborproject/magpie/internal/finding"
)

// Options controls rendering behavior shared across formats.
type Options struct {
	NoColor      bool
	NoTimestamps bool
	Timing       bool
	Compare      bool
	Filter       finding.Filter
}
