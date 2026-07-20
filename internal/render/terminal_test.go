package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/harborproject/magpie/internal/finding"
)

func TestTerminalNoColorHasNoEscapeCodes(t *testing.T) {
	var buf bytes.Buffer
	if err := Terminal(&buf, fixtureReport(), Options{NoColor: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Error("expected no ANSI escape codes when NoColor is set")
	}
}

func TestTerminalContainsDomainAndPaths(t *testing.T) {
	var buf bytes.Buffer
	if err := Terminal(&buf, fixtureReport(), Options{NoColor: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"example.org", "/.well-known/security.txt", "present", "/.well-known/webfinger", "absent"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestTerminalContainsFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := Terminal(&buf, fixtureReport(), Options{NoColor: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"SECTXT-004", "CORR-011", "DISCLOSURE"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestTerminalFiltersFindings(t *testing.T) {
	var buf bytes.Buffer
	opts := Options{NoColor: true, Filter: findingsAtLeastHigh()}
	if err := Terminal(&buf, fixtureReport(), opts); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "CORR-011") {
		t.Error("expected CORR-011 (low severity) to be filtered out")
	}
	if !strings.Contains(out, "SECTXT-004") {
		t.Error("expected SECTXT-004 (high severity) to remain")
	}
}

func TestTerminalNoTimestampsOmitsScanTime(t *testing.T) {
	var withTS, withoutTS bytes.Buffer
	rep := fixtureReport()
	Terminal(&withTS, rep, Options{NoColor: true})
	Terminal(&withoutTS, rep, Options{NoColor: true, NoTimestamps: true})
	if strings.Contains(withoutTS.String(), "2026-01-15") {
		t.Error("expected scan timestamp to be omitted with NoTimestamps")
	}
	if !strings.Contains(withTS.String(), "2026-01-15") {
		t.Error("expected scan timestamp to be present without NoTimestamps")
	}
}

func TestTerminalTimingFlagShowsDurations(t *testing.T) {
	var buf bytes.Buffer
	Terminal(&buf, fixtureReport(), Options{NoColor: true, Timing: true})
	if !strings.Contains(buf.String(), "ttfb=") {
		t.Error("expected ttfb column with --timing")
	}
}

func TestTerminalDeterministic(t *testing.T) {
	rep := fixtureReport()
	var a, b bytes.Buffer
	Terminal(&a, rep, Options{NoColor: true, NoTimestamps: true})
	Terminal(&b, rep, Options{NoColor: true, NoTimestamps: true})
	if a.String() != b.String() {
		t.Error("two renders of the same report should be byte-identical")
	}
}

func findingsAtLeastHigh() finding.Filter {
	return finding.Filter{MinSeverity: finding.SeverityHigh}
}
