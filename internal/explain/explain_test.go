package explain

import (
	"bytes"
	"strings"
	"testing"

	"github.com/harborproject/magpie/internal/finding"
)

func TestRegisterAndLookup(t *testing.T) {
	Register(Doc{ID: "TEST-001", Severity: finding.SeverityLow, Message: "test finding"})
	d, ok := Lookup("TEST-001")
	if !ok {
		t.Fatal("expected TEST-001 to be registered")
	}
	if d.Message != "test finding" {
		t.Errorf("Message = %q", d.Message)
	}
}

func TestLookupUnknown(t *testing.T) {
	if _, ok := Lookup("NOPE-999"); ok {
		t.Error("expected no doc for an unregistered ID")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	Register(Doc{ID: "TEST-002", Message: "first"})
	defer func() {
		if recover() == nil {
			t.Error("expected a panic on duplicate registration")
		}
	}()
	Register(Doc{ID: "TEST-002", Message: "second"})
}

func TestAllSortedByID(t *testing.T) {
	Register(Doc{ID: "TEST-010"})
	Register(Doc{ID: "TEST-003"})
	docs := All()
	var ids []string
	for _, d := range docs {
		if strings.HasPrefix(d.ID, "TEST-") {
			ids = append(ids, d.ID)
		}
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] > ids[i] {
			t.Fatalf("All() not sorted: %v", ids)
		}
	}
}

func TestRenderTextIncludesAllFields(t *testing.T) {
	d := Doc{
		ID: "TEST-050", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain,
		Category: finding.CategoryDisclosure, Message: "summary here", SpecRef: "RFC 0000",
		Explanation: "longform explanation text",
	}
	var buf bytes.Buffer
	if err := RenderText(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"TEST-050", "high", "certain", "disclosure", "summary here", "RFC 0000", "longform explanation text"} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderText output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderAllTextSeparatesEntries(t *testing.T) {
	docs := []Doc{
		{ID: "TEST-060", Message: "first"},
		{ID: "TEST-061", Message: "second"},
	}
	var buf bytes.Buffer
	if err := RenderAllText(&buf, docs); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "TEST-060") || !strings.Contains(out, "TEST-061") {
		t.Errorf("output missing an entry:\n%s", out)
	}
	if !strings.Contains(out, "---") {
		t.Error("expected a separator between entries")
	}
}

func TestRenderMarkdownStructure(t *testing.T) {
	docs := []Doc{{ID: "TEST-070", Severity: finding.SeverityInfo, Message: "md test", Explanation: "explanation body"}}
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, docs); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"# magpie finding reference", "## TEST-070", "**Severity**: info", "md test", "explanation body"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q:\n%s", want, out)
		}
	}
}

func TestWrapProducesNoOverlongLines(t *testing.T) {
	text := strings.Repeat("word ", 40)
	wrapped := wrap(text, 20)
	for _, line := range strings.Split(wrapped, "\n") {
		if len(line) > 20 && !strings.Contains(line, " ") {
			continue
		}
		if len(line) > 25 {
			t.Errorf("line too long (%d): %q", len(line), line)
		}
	}
}

func TestWrapEmptyString(t *testing.T) {
	if got := wrap("", 40); got != "" {
		t.Errorf("wrap(\"\") = %q, want empty", got)
	}
}
