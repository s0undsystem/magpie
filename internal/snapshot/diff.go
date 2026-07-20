package snapshot

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/report"
	"github.com/harborproject/magpie/internal/scan"
)

type SeverityChange struct {
	ID  string           `json:"id"`
	Old finding.Severity `json:"old"`
	New finding.Severity `json:"new"`
}

type Diff struct {
	Domain  string    `json:"domain"`
	OldScan time.Time `json:"old_scan"`
	NewScan time.Time `json:"new_scan"`

	PathsAppeared    []string `json:"paths_appeared,omitempty"`
	PathsDisappeared []string `json:"paths_disappeared,omitempty"`

	FindingsNew      []finding.Finding `json:"findings_new,omitempty"`
	FindingsResolved []finding.Finding `json:"findings_resolved,omitempty"`
	SeverityChanges  []SeverityChange  `json:"severity_changes,omitempty"`

	ExpiresDaysOld *int `json:"expires_days_old,omitempty"`
	ExpiresDaysNew *int `json:"expires_days_new,omitempty"`
}

func Compute(old, newRep report.Report) Diff {
	d := Diff{
		Domain:         newRep.Domain,
		OldScan:        old.ScannedAt,
		NewScan:        newRep.ScannedAt,
		ExpiresDaysOld: old.SecurityTxtExpiresDaysRemaining,
		ExpiresDaysNew: newRep.SecurityTxtExpiresDaysRemaining,
	}

	oldPresent := presentSet(old)
	newPresent := presentSet(newRep)
	for p := range newPresent {
		if !oldPresent[p] {
			d.PathsAppeared = append(d.PathsAppeared, p)
		}
	}
	for p := range oldPresent {
		if !newPresent[p] {
			d.PathsDisappeared = append(d.PathsDisappeared, p)
		}
	}
	sort.Strings(d.PathsAppeared)
	sort.Strings(d.PathsDisappeared)

	oldByID := findingsByID(old.Findings)
	newByID := findingsByID(newRep.Findings)

	var newIDs, resolvedIDs, commonIDs []string
	for id := range newByID {
		if _, ok := oldByID[id]; !ok {
			newIDs = append(newIDs, id)
		} else {
			commonIDs = append(commonIDs, id)
		}
	}
	for id := range oldByID {
		if _, ok := newByID[id]; !ok {
			resolvedIDs = append(resolvedIDs, id)
		}
	}
	sort.Strings(newIDs)
	sort.Strings(resolvedIDs)
	sort.Strings(commonIDs)

	for _, id := range newIDs {
		d.FindingsNew = append(d.FindingsNew, newByID[id])
	}
	for _, id := range resolvedIDs {
		d.FindingsResolved = append(d.FindingsResolved, oldByID[id])
	}
	for _, id := range commonIDs {
		o, n := oldByID[id], newByID[id]
		if o.Severity != n.Severity {
			d.SeverityChanges = append(d.SeverityChanges, SeverityChange{ID: id, Old: o.Severity, New: n.Severity})
		}
	}

	return d
}

func presentSet(rep report.Report) map[string]bool {
	set := map[string]bool{}
	for _, p := range rep.Paths {
		if p.Presence == scan.PresencePresent {
			set[p.Path] = true
		}
	}
	return set
}

func findingsByID(findings []finding.Finding) map[string]finding.Finding {
	m := make(map[string]finding.Finding, len(findings))
	for _, f := range findings {
		if _, exists := m[f.ID]; !exists {
			m[f.ID] = f
		}
	}
	return m
}

func (d Diff) HasChanges() bool {
	return len(d.PathsAppeared) > 0 || len(d.PathsDisappeared) > 0 ||
		len(d.FindingsNew) > 0 || len(d.FindingsResolved) > 0 || len(d.SeverityChanges) > 0 ||
		expiresChanged(d.ExpiresDaysOld, d.ExpiresDaysNew)
}

func (d Diff) HasNewMediumOrHigher() bool {
	for _, f := range d.FindingsNew {
		if f.Severity.Rank() >= finding.SeverityMedium.Rank() {
			return true
		}
	}
	for _, c := range d.SeverityChanges {
		if c.New.Rank() >= finding.SeverityMedium.Rank() && c.New.Rank() > c.Old.Rank() {
			return true
		}
	}
	return false
}

func expiresChanged(old, new_ *int) bool {
	if old == nil || new_ == nil {
		return false
	}
	return *old != *new_
}

func (d Diff) RenderText() string {
	var b strings.Builder
	if !d.HasChanges() {
		b.WriteString("no changes since last snapshot\n")
		return b.String()
	}

	for _, p := range d.PathsAppeared {
		fmt.Fprintf(&b, "+ /.well-known/%s appeared\n", p)
	}
	for _, p := range d.PathsDisappeared {
		fmt.Fprintf(&b, "- /.well-known/%s disappeared\n", p)
	}
	for _, f := range d.FindingsNew {
		fmt.Fprintf(&b, "+ %s (%s) %s\n", f.ID, f.Severity, f.Message)
	}
	for _, f := range d.FindingsResolved {
		fmt.Fprintf(&b, "- %s resolved\n", f.ID)
	}
	for _, c := range d.SeverityChanges {
		fmt.Fprintf(&b, "~ %s severity changed: %s -> %s\n", c.ID, c.Old, c.New)
	}
	if expiresChanged(d.ExpiresDaysOld, d.ExpiresDaysNew) {
		fmt.Fprintf(&b, "~ security.txt Expires countdown: %d -> %d day(s)\n", *d.ExpiresDaysOld, *d.ExpiresDaysNew)
	}
	return b.String()
}
