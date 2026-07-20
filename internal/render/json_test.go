package render

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/harborproject/magpie/internal/report"
)

func TestJSONRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, fixtureReport(), Options{}); err != nil {
		t.Fatal(err)
	}
	var decoded report.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output did not decode as a Report: %v", err)
	}
	if decoded.Domain != "example.org" {
		t.Errorf("Domain = %q", decoded.Domain)
	}
	if decoded.SchemaVersion != report.SchemaVersion {
		t.Errorf("SchemaVersion = %d", decoded.SchemaVersion)
	}
	if len(decoded.Findings) != 2 {
		t.Errorf("Findings count = %d, want 2", len(decoded.Findings))
	}
}

func TestJSONAppliesFilter(t *testing.T) {
	var buf bytes.Buffer
	opts := Options{Filter: findingsAtLeastHigh()}
	if err := JSON(&buf, fixtureReport(), opts); err != nil {
		t.Fatal(err)
	}
	var decoded report.Report
	json.Unmarshal(buf.Bytes(), &decoded)
	if len(decoded.Findings) != 1 || decoded.Findings[0].ID != "SECTXT-004" {
		t.Errorf("filtered findings = %+v", decoded.Findings)
	}
}

func TestJSONNoTimestampsZeroesTime(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, fixtureReport(), Options{NoTimestamps: true}); err != nil {
		t.Fatal(err)
	}
	var decoded report.Report
	json.Unmarshal(buf.Bytes(), &decoded)
	if !decoded.ScannedAt.IsZero() {
		t.Errorf("ScannedAt = %v, want zero", decoded.ScannedAt)
	}
	for _, p := range decoded.Paths {
		if p.TTFB != 0 || p.Total != 0 {
			t.Errorf("expected zeroed timing with NoTimestamps, got %+v", p)
		}
	}
}

func TestJSONDoesNotMutateOriginalReport(t *testing.T) {
	rep := fixtureReport()
	originalScannedAt := rep.ScannedAt
	var buf bytes.Buffer
	JSON(&buf, rep, Options{NoTimestamps: true})
	if rep.ScannedAt != originalScannedAt {
		t.Error("JSON rendering with NoTimestamps must not mutate the caller's Report")
	}
}

func TestJSONDeterministic(t *testing.T) {
	rep := fixtureReport()
	rep.ScannedAt = time.Time{} // hold timestamp fixed so we compare full bytes
	for i := range rep.Paths {
		rep.Paths[i].TTFB, rep.Paths[i].Total = 0, 0
	}
	var a, b bytes.Buffer
	JSON(&a, rep, Options{})
	JSON(&b, rep, Options{})
	if a.String() != b.String() {
		t.Error("two renders of the same report should be byte-identical")
	}
}
