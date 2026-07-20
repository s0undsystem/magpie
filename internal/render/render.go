package render

import (
	"github.com/s0undsystem/magpie/internal/finding"
)

type Options struct {
	NoColor      bool
	NoTimestamps bool
	Timing       bool
	Compare      bool
	ShowBanner   bool
	Filter       finding.Filter
}
