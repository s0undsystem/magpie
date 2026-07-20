// Package compare provides magpie's embedded reference corpus: a small,
// curated (not statistically sampled) description of what well-run domains
// typically publish under /.well-known/, used by --compare to give scan
// results context. See corpus.json's methodology field for how to update it.
package compare

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed corpus.json
var embeddedCorpus []byte

// PathBaseline is one path's reference expectation.
type PathBaseline struct {
	Path           string `json:"path"`
	PercentPresent int    `json:"percent_present"`
	Note           string `json:"note,omitempty"`
}

// Corpus is the full embedded reference sample.
type Corpus struct {
	Version     int            `json:"version"`
	Updated     string         `json:"updated"`
	Description string         `json:"description"`
	Methodology string         `json:"methodology"`
	SampleSize  int            `json:"sample_size"`
	Paths       []PathBaseline `json:"paths"`
}

// Load parses the embedded corpus.
func Load() (Corpus, error) {
	var c Corpus
	if err := json.Unmarshal(embeddedCorpus, &c); err != nil {
		return Corpus{}, fmt.Errorf("compare: parsing embedded corpus.json: %w", err)
	}
	return c, nil
}

// Row is one path's baseline alongside whether the scanned target has it.
type Row struct {
	Path           string
	TargetPresent  bool
	PercentPresent int
	Note           string
}

// Rows builds a comparison table from the corpus and the target's set of
// present paths, in corpus file order.
func Rows(c Corpus, targetPresentPaths map[string]bool) []Row {
	rows := make([]Row, 0, len(c.Paths))
	for _, p := range c.Paths {
		rows = append(rows, Row{
			Path:           p.Path,
			TargetPresent:  targetPresentPaths[p.Path],
			PercentPresent: p.PercentPresent,
			Note:           p.Note,
		})
	}
	return rows
}
