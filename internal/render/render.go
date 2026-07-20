package render

import (
	"github.com/harborproject/magpie/internal/finding"
)

type Options struct {
	NoColor      bool
	NoTimestamps bool
	Timing       bool
	Compare      bool
	Filter       finding.Filter
}
