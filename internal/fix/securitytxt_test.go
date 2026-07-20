package fix

import (
	"strings"
	"testing"
	"time"

	"github.com/harborproject/magpie/internal/scan"
	"github.com/harborproject/magpie/internal/validate"
)

var fixedNow = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

func TestSecurityTxtFromScratchHasTODOMarkers(t *testing.T) {
	out := SecurityTxt("example.org", nil, fixedNow)
	if !strings.Contains(out, "TODO") {
		t.Error("expected at least one TODO marker when nothing was discovered")
	}
	if !strings.Contains(out, "Contact: mailto:security@example.org") {
		t.Errorf("expected a generated Contact fallback, got:\n%s", out)
	}
	if !strings.Contains(out, "Canonical: https://example.org/.well-known/security.txt") {
		t.Errorf("expected a Canonical field, got:\n%s", out)
	}
}

func TestSecurityTxtExpiresIsOneYearOut(t *testing.T) {
	out := SecurityTxt("example.org", nil, fixedNow)
	want := "Expires: " + fixedNow.Add(OneYear).Format(time.RFC3339)
	if !strings.Contains(out, want) {
		t.Errorf("expected %q in output:\n%s", want, out)
	}
}

func TestSecurityTxtReusesDiscoveredValues(t *testing.T) {
	existing := []byte("Contact: mailto:sec@example.org\nExpires: 2020-01-01T00:00:00Z\nPolicy: https://example.org/policy\nEncryption: https://example.org/key.txt\nPreferred-Languages: en, fr\n")
	out := SecurityTxt("example.org", existing, fixedNow)

	for _, want := range []string{
		"Contact: mailto:sec@example.org",
		"Policy: https://example.org/policy",
		"Encryption: https://example.org/key.txt",
		"Preferred-Languages: en, fr",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected discovered value %q preserved, got:\n%s", want, out)
		}
	}
	// A discovered Contact must not also get the generated fallback comment.
	if strings.Contains(out, "TODO: magpie could not discover a contact method") {
		t.Error("did not expect the contact TODO comment when Contact was discovered")
	}
	// The stale Expires must be refreshed, not carried over.
	if strings.Contains(out, "2020-01-01") {
		t.Error("expected the expired date to be refreshed, not preserved")
	}
}

func TestSecurityTxtMultipleContactsPreserved(t *testing.T) {
	existing := []byte("Contact: mailto:sec@example.org\nContact: https://example.org/report\nExpires: 2020-01-01T00:00:00Z\n")
	out := SecurityTxt("example.org", existing, fixedNow)
	if !strings.Contains(out, "Contact: mailto:sec@example.org") || !strings.Contains(out, "Contact: https://example.org/report") {
		t.Errorf("expected both Contact values preserved, got:\n%s", out)
	}
}

// TestSecurityTxtValidatesClean is a regression guard: the generated file
// (from scratch, worst case) must itself pass SecurityTxtValidator with no
// missing-field or malformed-Expires findings, so --fix never produces
// output that magpie's own scan would immediately flag as broken.
func TestSecurityTxtValidatesClean(t *testing.T) {
	out := SecurityTxt("example.org", nil, fixedNow)

	result := scan.Result{
		Presence: scan.PresencePresent,
		URL:      "https://example.org/.well-known/security.txt",
		Body:     []byte(out),
	}
	vout := validate.SecurityTxtValidator{}.Validate(validate.Context{Host: "example.org", Result: result})

	for _, f := range vout.Findings {
		switch f.ID {
		case "SECTXT-001", "SECTXT-002", "SECTXT-003", "SECTXT-004", "SECTXT-005", "SECTXT-007", "SECTXT-008", "SECTXT-012":
			t.Errorf("generated security.txt failed its own validator: %s: %s", f.ID, f.Message)
		}
	}
}

func TestSecurityTxtDeterministic(t *testing.T) {
	a := SecurityTxt("example.org", nil, fixedNow)
	b := SecurityTxt("example.org", nil, fixedNow)
	if a != b {
		t.Error("two generations with the same inputs should be byte-identical")
	}
}
