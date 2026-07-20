package render

import (
	"bytes"
	"strings"
	"testing"
)

func TestMarkdownContainsExpectedSections(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, fixtureReport(), Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"# magpie report: example.org",
		"## Well-known paths",
		"`/.well-known/security.txt`",
		"## Findings (2)",
		"SECTXT-004",
		"## Inference",
		"Okta",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q:\n%s", want, out)
		}
	}
}

func TestMarkdownFiltersFindings(t *testing.T) {
	var buf bytes.Buffer
	Markdown(&buf, fixtureReport(), Options{Filter: findingsAtLeastHigh()})
	out := buf.String()
	if strings.Contains(out, "CORR-011") {
		t.Error("expected low-severity finding to be filtered out")
	}
	if !strings.Contains(out, "Findings (1)") {
		t.Errorf("expected finding count header to reflect the filter, got:\n%s", out)
	}
}

func TestMarkdownEscapesPipes(t *testing.T) {
	if got := mdEscape("a | b"); got != "a \\| b" {
		t.Errorf("mdEscape() = %q", got)
	}
}

func TestMarkdownDeterministic(t *testing.T) {
	rep := fixtureReport()
	var a, b bytes.Buffer
	Markdown(&a, rep, Options{NoTimestamps: true})
	Markdown(&b, rep, Options{NoTimestamps: true})
	if a.String() != b.String() {
		t.Error("two renders of the same report should be byte-identical")
	}
}
