package render

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/harborproject/magpie/internal/finding"
)

func TestSARIFValidJSONStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, fixtureReport(), Options{}); err != nil {
		t.Fatal(err)
	}
	var log map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", log["version"])
	}
	if log["$schema"] == nil {
		t.Error("missing $schema")
	}
	runs, ok := log["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v", log["runs"])
	}
}

func TestSARIFSeverityToLevelMapping(t *testing.T) {
	cases := map[string]string{
		"high": "error", "medium": "warning", "low": "note", "info": "note",
	}
	for sev, wantLevel := range cases {
		var buf bytes.Buffer
		rep := fixtureReport()
		rep.Findings = rep.Findings[:1]
		rep.Findings[0].Severity = finding.Severity(sev)
		if err := SARIF(&buf, rep, Options{}); err != nil {
			t.Fatal(err)
		}
		var log sarifLog
		json.Unmarshal(buf.Bytes(), &log)
		if len(log.Runs[0].Results) != 1 {
			t.Fatalf("expected 1 result for severity %s", sev)
		}
		if got := log.Runs[0].Results[0].Level; got != wantLevel {
			t.Errorf("severity %s -> level %s, want %s", sev, got, wantLevel)
		}
	}
}

func TestSARIFIncludesRuleDescriptions(t *testing.T) {
	var buf bytes.Buffer
	rep := fixtureReport()
	rep.Findings = []finding.Finding{{ID: "SECTXT-004", Severity: finding.SeverityHigh}}
	if err := SARIF(&buf, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	json.Unmarshal(buf.Bytes(), &log)
	if len(log.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}
	rule := log.Runs[0].Tool.Driver.Rules[0]
	if rule.ID != "SECTXT-004" {
		t.Errorf("rule.ID = %q", rule.ID)
	}
	if rule.FullDescription.Text == "" {
		t.Error("expected a non-empty FullDescription for a known validator finding ID")
	}
}

func TestSARIFAppliesFilter(t *testing.T) {
	var buf bytes.Buffer
	SARIF(&buf, fixtureReport(), Options{Filter: findingsAtLeastHigh()})
	var log sarifLog
	json.Unmarshal(buf.Bytes(), &log)
	if len(log.Runs[0].Results) != 1 {
		t.Errorf("expected 1 filtered result, got %d", len(log.Runs[0].Results))
	}
}

func TestSARIFDeterministic(t *testing.T) {
	rep := fixtureReport()
	var a, b bytes.Buffer
	SARIF(&a, rep, Options{})
	SARIF(&b, rep, Options{})
	if a.String() != b.String() {
		t.Error("two renders of the same report should be byte-identical")
	}
}
