package explain

import (
	"sort"

	"github.com/s0undsystem/magpie/internal/finding"
)

type Doc struct {
	ID          string
	Severity    finding.Severity
	Confidence  finding.Confidence
	Category    finding.Category
	Message     string
	SpecRef     string
	Explanation string
}

var registry = map[string]Doc{}

func Register(d Doc) {
	if _, exists := registry[d.ID]; exists {
		panic("explain: duplicate doc registered for " + d.ID)
	}
	registry[d.ID] = d
}

func Lookup(id string) (Doc, bool) {
	d, ok := registry[id]
	return d, ok
}

func All() []Doc {
	docs := make([]Doc, 0, len(registry))
	for _, d := range registry {
		docs = append(docs, d)
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].ID < docs[j].ID })
	return docs
}
