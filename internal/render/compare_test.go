package render

import (
	"bytes"
	"strings"
	"testing"
)

func TestTerminalCompareSectionOmittedByDefault(t *testing.T) {
	var buf bytes.Buffer
	Terminal(&buf, fixtureReport(), Options{NoColor: true})
	if strings.Contains(buf.String(), "COMPARE TO REFERENCE CORPUS") {
		t.Error("did not expect a compare section without opts.Compare")
	}
}

func TestTerminalCompareSectionIncluded(t *testing.T) {
	var buf bytes.Buffer
	Terminal(&buf, fixtureReport(), Options{NoColor: true, Compare: true})
	out := buf.String()
	if !strings.Contains(out, "COMPARE TO REFERENCE CORPUS") {
		t.Fatal("expected a compare section with opts.Compare")
	}
	if !strings.Contains(out, "/.well-known/security.txt") || !strings.Contains(out, "present") {
		t.Errorf("expected security.txt marked present in comparison:\n%s", out)
	}
}

func TestTerminalCompareDeterministic(t *testing.T) {
	rep := fixtureReport()
	var a, b bytes.Buffer
	Terminal(&a, rep, Options{NoColor: true, Compare: true, NoTimestamps: true})
	Terminal(&b, rep, Options{NoColor: true, Compare: true, NoTimestamps: true})
	if a.String() != b.String() {
		t.Error("two renders with --compare should be byte-identical")
	}
}
