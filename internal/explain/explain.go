// Package explain holds longform documentation for every finding ID a
// validator can emit, registered by each validator's own source file so the
// explanation can never drift out of sync with the code that produces the
// finding. Correlation rule documentation lives separately, alongside each
// rule's condition in internal/correlate/rules.json, for the same reason.
package explain

import (
	"sort"

	"github.com/harborproject/magpie/internal/finding"
)

// Doc is the longform explanation for one finding ID: what it means, why it
// matters, and how to fix it, plus the metadata needed to render it without
// having run a scan.
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

// Register adds a Doc to the registry. It panics on a duplicate ID, which
// can only happen from a programming error at init time.
func Register(d Doc) {
	if _, exists := registry[d.ID]; exists {
		panic("explain: duplicate doc registered for " + d.ID)
	}
	registry[d.ID] = d
}

// Lookup returns the Doc for a finding ID, if any validator registered one.
func Lookup(id string) (Doc, bool) {
	d, ok := registry[id]
	return d, ok
}

// All returns every registered Doc, sorted by ID.
func All() []Doc {
	docs := make([]Doc, 0, len(registry))
	for _, d := range registry {
		docs = append(docs, d)
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].ID < docs[j].ID })
	return docs
}
