package finding

import "sort"

type Finding struct {
	ID string `json:"id"`

	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Category   Category   `json:"category"`

	Message string `json:"message"`

	Evidence string `json:"evidence"`

	SpecRef string `json:"spec_ref,omitempty"`
}

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

type Filter struct {
	MinSeverity   Severity
	MinConfidence Confidence
	Categories    []Category
}

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

func (flt Filter) Apply(findings []Finding) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if flt.Matches(f) {
			out = append(out, f)
		}
	}
	return out
}

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

type CategoryGroup struct {
	Category Category
	Findings []Finding
}
