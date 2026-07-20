package snapshot

import (
	"strings"
	"testing"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/report"
	"github.com/harborproject/magpie/internal/scan"
)

func ptr(i int) *int { return &i }

func TestComputePathAppearedAndDisappeared(t *testing.T) {
	old := report.Report{Paths: []report.PathResult{
		{Path: "security.txt", Presence: scan.PresencePresent},
		{Path: "webfinger", Presence: scan.PresencePresent},
	}}
	newRep := report.Report{Paths: []report.PathResult{
		{Path: "security.txt", Presence: scan.PresenceAbsent},
		{Path: "assetlinks.json", Presence: scan.PresencePresent},
	}}
	d := Compute(old, newRep)
	if len(d.PathsAppeared) != 1 || d.PathsAppeared[0] != "assetlinks.json" {
		t.Errorf("PathsAppeared = %v", d.PathsAppeared)
	}
	if len(d.PathsDisappeared) != 2 {
		t.Errorf("PathsDisappeared = %v, want [security.txt webfinger]", d.PathsDisappeared)
	}
}

func TestComputeNewAndResolvedFindings(t *testing.T) {
	old := report.Report{Findings: []finding.Finding{{ID: "CORR-008", Severity: finding.SeverityMedium}}}
	newRep := report.Report{Findings: []finding.Finding{{ID: "SECTXT-004", Severity: finding.SeverityHigh}}}
	d := Compute(old, newRep)
	if len(d.FindingsNew) != 1 || d.FindingsNew[0].ID != "SECTXT-004" {
		t.Errorf("FindingsNew = %+v", d.FindingsNew)
	}
	if len(d.FindingsResolved) != 1 || d.FindingsResolved[0].ID != "CORR-008" {
		t.Errorf("FindingsResolved = %+v", d.FindingsResolved)
	}
}

func TestComputeSeverityChange(t *testing.T) {
	old := report.Report{Findings: []finding.Finding{{ID: "CORR-003", Severity: finding.SeverityMedium}}}
	newRep := report.Report{Findings: []finding.Finding{{ID: "CORR-003", Severity: finding.SeverityHigh}}}
	d := Compute(old, newRep)
	if len(d.SeverityChanges) != 1 {
		t.Fatalf("SeverityChanges = %+v", d.SeverityChanges)
	}
	c := d.SeverityChanges[0]
	if c.ID != "CORR-003" || c.Old != finding.SeverityMedium || c.New != finding.SeverityHigh {
		t.Errorf("SeverityChange = %+v", c)
	}
}

func TestComputeNoChangeSameSeverity(t *testing.T) {
	old := report.Report{Findings: []finding.Finding{{ID: "CORR-003", Severity: finding.SeverityMedium}}}
	newRep := report.Report{Findings: []finding.Finding{{ID: "CORR-003", Severity: finding.SeverityMedium}}}
	d := Compute(old, newRep)
	if len(d.SeverityChanges) != 0 || len(d.FindingsNew) != 0 || len(d.FindingsResolved) != 0 {
		t.Errorf("expected no changes, got %+v", d)
	}
}

func TestComputeExpiresCountdown(t *testing.T) {
	old := report.Report{SecurityTxtExpiresDaysRemaining: ptr(45)}
	newRep := report.Report{SecurityTxtExpiresDaysRemaining: ptr(12)}
	d := Compute(old, newRep)
	if d.ExpiresDaysOld == nil || *d.ExpiresDaysOld != 45 {
		t.Errorf("ExpiresDaysOld = %v", d.ExpiresDaysOld)
	}
	if d.ExpiresDaysNew == nil || *d.ExpiresDaysNew != 12 {
		t.Errorf("ExpiresDaysNew = %v", d.ExpiresDaysNew)
	}
	if !d.HasChanges() {
		t.Error("expected HasChanges() true when Expires countdown moved")
	}
}

func TestHasChangesFalseWhenIdentical(t *testing.T) {
	rep := report.Report{
		Paths:    []report.PathResult{{Path: "security.txt", Presence: scan.PresencePresent}},
		Findings: []finding.Finding{{ID: "CORR-011", Severity: finding.SeverityLow}},
	}
	d := Compute(rep, rep)
	if d.HasChanges() {
		t.Errorf("expected no changes when comparing identical reports, got %+v", d)
	}
}

func TestHasNewMediumOrHigher(t *testing.T) {
	old := report.Report{}
	newRep := report.Report{Findings: []finding.Finding{{ID: "CORR-004", Severity: finding.SeverityHigh}}}
	d := Compute(old, newRep)
	if !d.HasNewMediumOrHigher() {
		t.Error("expected HasNewMediumOrHigher() true for a new high-severity finding")
	}
}

func TestHasNewMediumOrHigherFalseForLowSeverity(t *testing.T) {
	old := report.Report{}
	newRep := report.Report{Findings: []finding.Finding{{ID: "CORR-012", Severity: finding.SeverityInfo}}}
	d := Compute(old, newRep)
	if d.HasNewMediumOrHigher() {
		t.Error("did not expect HasNewMediumOrHigher() for an info-severity new finding")
	}
}

func TestHasNewMediumOrHigherTrueForEscalatedSeverity(t *testing.T) {
	old := report.Report{Findings: []finding.Finding{{ID: "CORR-003", Severity: finding.SeverityLow}}}
	newRep := report.Report{Findings: []finding.Finding{{ID: "CORR-003", Severity: finding.SeverityHigh}}}
	d := Compute(old, newRep)
	if !d.HasNewMediumOrHigher() {
		t.Error("expected HasNewMediumOrHigher() true when an existing finding escalates to high")
	}
}

func TestRenderTextNoChanges(t *testing.T) {
	rep := report.Report{}
	d := Compute(rep, rep)
	if got := d.RenderText(); !strings.Contains(got, "no changes") {
		t.Errorf("RenderText() = %q", got)
	}
}

func TestRenderTextIncludesAllChangeTypes(t *testing.T) {
	old := report.Report{
		Paths:                           []report.PathResult{{Path: "security.txt", Presence: scan.PresencePresent}},
		Findings:                        []finding.Finding{{ID: "CORR-003", Severity: finding.SeverityLow}},
		SecurityTxtExpiresDaysRemaining: ptr(45),
	}
	newRep := report.Report{
		Paths:                           []report.PathResult{{Path: "assetlinks.json", Presence: scan.PresencePresent}},
		Findings:                        []finding.Finding{{ID: "CORR-003", Severity: finding.SeverityHigh}, {ID: "SECTXT-004", Severity: finding.SeverityHigh, Message: "expired"}},
		SecurityTxtExpiresDaysRemaining: ptr(2),
	}
	d := Compute(old, newRep)
	out := d.RenderText()
	for _, want := range []string{"assetlinks.json appeared", "security.txt disappeared", "SECTXT-004", "CORR-003 severity changed", "45 -> 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderText() missing %q:\n%s", want, out)
		}
	}
}
