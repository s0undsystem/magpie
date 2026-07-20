package report

import (
	"testing"
	"time"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/infer"
	"github.com/harborproject/magpie/internal/scan"
)

func TestBuildSortsPathsByName(t *testing.T) {
	results := []scan.Result{
		{Path: "webfinger", Presence: scan.PresenceAbsent},
		{Path: "acme-challenge", Presence: scan.PresencePresent},
		{Path: "mta-sts.txt", Presence: scan.PresenceAbsent},
	}
	rep := Build("example.org", time.Now(), results, scan.Control{}, nil, infer.Result{}, nil)
	want := []string{"acme-challenge", "mta-sts.txt", "webfinger"}
	for i, w := range want {
		if rep.Paths[i].Path != w {
			t.Errorf("Paths[%d] = %q, want %q", i, rep.Paths[i].Path, w)
		}
	}
}

func TestBuildSortsFindings(t *testing.T) {
	findings := []finding.Finding{
		{ID: "CORR-002", Severity: finding.SeverityLow, Category: finding.CategoryMobile},
		{ID: "SECTXT-004", Severity: finding.SeverityHigh, Category: finding.CategoryDisclosure},
	}
	rep := Build("example.org", time.Now(), nil, scan.Control{}, findings, infer.Result{}, nil)
	if rep.Findings[0].ID != "SECTXT-004" {
		t.Errorf("Findings[0] = %s, want SECTXT-004 (disclosure/high sorts first)", rep.Findings[0].ID)
	}
}

func TestBuildDoesNotMutateInputSlices(t *testing.T) {
	findings := []finding.Finding{
		{ID: "B", Severity: finding.SeverityLow},
		{ID: "A", Severity: finding.SeverityLow},
	}
	original := append([]finding.Finding(nil), findings...)
	_ = Build("example.org", time.Now(), nil, scan.Control{}, findings, infer.Result{}, nil)
	for i := range findings {
		if findings[i] != original[i] {
			t.Errorf("Build mutated caller's findings slice at %d: %+v vs %+v", i, findings[i], original[i])
		}
	}
}

func TestPresentPaths(t *testing.T) {
	results := []scan.Result{
		{Path: "a", Presence: scan.PresencePresent},
		{Path: "b", Presence: scan.PresenceAbsent},
		{Path: "c", Presence: scan.PresencePresent},
	}
	rep := Build("example.org", time.Now(), results, scan.Control{}, nil, infer.Result{}, nil)
	present := rep.PresentPaths()
	if len(present) != 2 {
		t.Fatalf("PresentPaths() returned %d, want 2", len(present))
	}
	if present[0].Path != "a" || present[1].Path != "c" {
		t.Errorf("PresentPaths() = %+v", present)
	}
}

func TestCountBySeverity(t *testing.T) {
	findings := []finding.Finding{
		{ID: "A", Severity: finding.SeverityHigh},
		{ID: "B", Severity: finding.SeverityHigh},
		{ID: "C", Severity: finding.SeverityLow},
	}
	rep := Build("example.org", time.Now(), nil, scan.Control{}, findings, infer.Result{}, nil)
	counts := rep.CountBySeverity()
	if counts[finding.SeverityHigh] != 2 || counts[finding.SeverityLow] != 1 {
		t.Errorf("CountBySeverity() = %+v", counts)
	}
}

func TestSchemaVersionSet(t *testing.T) {
	rep := Build("example.org", time.Now(), nil, scan.Control{}, nil, infer.Result{}, nil)
	if rep.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", rep.SchemaVersion, SchemaVersion)
	}
}
