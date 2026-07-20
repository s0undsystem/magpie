package compare

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed corpus.json
var embeddedCorpus []byte

type PathBaseline struct {
	Path           string `json:"path"`
	PercentPresent int    `json:"percent_present"`
	Note           string `json:"note,omitempty"`
}

type Corpus struct {
	Version     int            `json:"version"`
	Updated     string         `json:"updated"`
	Description string         `json:"description"`
	Methodology string         `json:"methodology"`
	SampleSize  int            `json:"sample_size"`
	Paths       []PathBaseline `json:"paths"`
}

func Load() (Corpus, error) {
	var c Corpus
	if err := json.Unmarshal(embeddedCorpus, &c); err != nil {
		return Corpus{}, fmt.Errorf("compare: parsing embedded corpus.json: %w", err)
	}
	return c, nil
}

type Row struct {
	Path           string
	TargetPresent  bool
	PercentPresent int
	Note           string
}

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
