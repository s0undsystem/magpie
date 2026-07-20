// Package finding defines the finding model shared by every validator, the
// correlation engine, and the inference layer.
package finding

import "sort"

// Finding is a single reportable observation. It is produced either by a
// validator reading a well-known document directly, or by the correlation
// engine reasoning across multiple documents.
type Finding struct {
	// ID is a stable identifier, e.g. "SECTXT-004" or "CORR-011". IDs are
	// never reused and never renumbered.
	ID string `json:"id"`

	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Category   Category   `json:"category"`

	// Message is one sentence of plain practitioner language. No marketing
	// tone.
	Message string `json:"message"`

	// Evidence is the specific value or path that triggered the finding.
	Evidence string `json:"evidence"`

	// SpecRef is the RFC or spec section this finding relates to, where
	// applicable.
	SpecRef string `json:"spec_ref,omitempty"`
}

// Sort orders findings deterministically: by category (canonical order),
// then by severity descending, then by ID ascending. This is the order the
// terminal, markdown, and JSON renderers all rely on for byte-identical
// repeat output.
func Sort(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Category.Rank() != b.Category.Rank() {
			return a.Category.Rank() < b.Category.Rank()
		}
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.ID < b.ID
	})
}

// Filter describes the minimum thresholds and category allow-list used to
// narrow a finding set for display, mirroring the --min-severity,
// --min-confidence, and --category CLI flags.
type Filter struct {
	MinSeverity   Severity
	MinConfidence Confidence
	Categories    []Category // empty means "all categories"
}

// Matches reports whether f passes the filter.
func (flt Filter) Matches(f Finding) bool {
	if flt.MinSeverity != "" && f.Severity.Rank() < flt.MinSeverity.Rank() {
		return false
	}
	if flt.MinConfidence != "" && f.Confidence.Rank() < flt.MinConfidence.Rank() {
		return false
	}
	if len(flt.Categories) > 0 {
		match := false
		for _, c := range flt.Categories {
			if c == f.Category {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

// Apply returns the subset of findings passing the filter, in their
// original relative order.
func (flt Filter) Apply(findings []Finding) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if flt.Matches(f) {
			out = append(out, f)
		}
	}
	return out
}

// GroupByCategory splits sorted findings into per-category slices, in
// canonical category order. Call Sort first if the input isn't already
// sorted; GroupByCategory does not re-sort within a category.
func GroupByCategory(findings []Finding) []CategoryGroup {
	groups := map[Category][]Finding{}
	for _, f := range findings {
		groups[f.Category] = append(groups[f.Category], f)
	}

	cats := make([]Category, 0, len(groups))
	for c := range groups {
		cats = append(cats, c)
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i].Rank() < cats[j].Rank() })

	out := make([]CategoryGroup, 0, len(cats))
	for _, c := range cats {
		out = append(out, CategoryGroup{Category: c, Findings: groups[c]})
	}
	return out
}

// CategoryGroup is a category and the findings within it, used by renderers.
type CategoryGroup struct {
	Category Category
	Findings []Finding
}
