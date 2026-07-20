package validate

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/s0undsystem/magpie/internal/finding"
	"github.com/s0undsystem/magpie/internal/scan"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/securitytxt/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return data
}

func hasFinding(findings []finding.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestSecurityTxtValidator_Path(t *testing.T) {
	if got := (SecurityTxtValidator{}).Path(); got != "security.txt" {
		t.Errorf("Path() = %q, want %q", got, "security.txt")
	}
}

func TestSecurityTxtValidator_NotPresentSkipsValidation(t *testing.T) {
	for _, presence := range []scan.Presence{scan.PresenceAbsent, scan.PresenceSoft404, scan.PresenceError, scan.PresenceRedirectedOffsite} {
		out := SecurityTxtValidator{}.Validate(Context{Result: scan.Result{Presence: presence}})
		if len(out.Findings) != 0 {
			t.Errorf("presence %q: got %d findings, want 0", presence, len(out.Findings))
		}
	}
}

func TestSecurityTxtValidator_MissingRequiredFields(t *testing.T) {
	body := readFixture(t, "missing_fields.txt")
	out := SecurityTxtValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		URL:      "https://example.org/.well-known/security.txt",
		Body:     body,
	}})
	if !hasFinding(out.Findings, "SECTXT-001") {
		t.Error("expected SECTXT-001 (missing Contact)")
	}
	if !hasFinding(out.Findings, "SECTXT-002") {
		t.Error("expected SECTXT-002 (missing Expires)")
	}
}

func TestSecurityTxtValidator_ExpiresInPast(t *testing.T) {
	body := []byte(fmt.Sprintf("Contact: mailto:security@example.org\nExpires: %s\n",
		time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339)))
	out := SecurityTxtValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		URL:      "https://example.org/.well-known/security.txt",
		Body:     body,
	}})
	if !hasFinding(out.Findings, "SECTXT-004") {
		t.Error("expected SECTXT-004 (Expires in the past)")
	}
	if hasFinding(out.Findings, "SECTXT-001") || hasFinding(out.Findings, "SECTXT-002") {
		t.Error("did not expect missing-field findings when both fields are present")
	}
}

func TestSecurityTxtValidator_ExpiresTooFarOut(t *testing.T) {
	body := []byte(fmt.Sprintf("Contact: mailto:security@example.org\nExpires: %s\n",
		time.Now().Add(400*24*time.Hour).UTC().Format(time.RFC3339)))
	out := SecurityTxtValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		URL:      "https://example.org/.well-known/security.txt",
		Body:     body,
	}})
	if !hasFinding(out.Findings, "SECTXT-005") {
		t.Error("expected SECTXT-005 (Expires more than one year out)")
	}
}

func TestSecurityTxtValidator_ExpiresValidReportsdaysRemaining(t *testing.T) {
	body := []byte(fmt.Sprintf("Contact: mailto:security@example.org\nExpires: %s\n",
		time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339)))
	out := SecurityTxtValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		URL:      "https://example.org/.well-known/security.txt",
		Body:     body,
	}})
	if !hasFinding(out.Findings, "SECTXT-006") {
		t.Error("expected SECTXT-006 (Expires valid, days remaining reported)")
	}
	if days, ok := out.Facts["expires_days_remaining"]; !ok || days != "89" && days != "90" {
		t.Errorf("expires_days_remaining fact = %q, want ~90", days)
	}
}

func TestSecurityTxtValidator_ExpiresMalformed(t *testing.T) {
	body := []byte("Contact: mailto:security@example.org\nExpires: not-a-date\n")
	out := SecurityTxtValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		URL:      "https://example.org/.well-known/security.txt",
		Body:     body,
	}})
	if !hasFinding(out.Findings, "SECTXT-003") {
		t.Error("expected SECTXT-003 (Expires does not parse as ISO 8601)")
	}
}

func TestSecurityTxtValidator_CanonicalMismatch(t *testing.T) {
	body := readFixture(t, "canonical_mismatch.txt")
	out := SecurityTxtValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		URL:      "https://example.org/.well-known/security.txt",
		Body:     body,
	}})
	if !hasFinding(out.Findings, "SECTXT-007") {
		t.Error("expected SECTXT-007 (Canonical mismatch)")
	}
}

func TestSecurityTxtValidator_CanonicalMatchNoFinding(t *testing.T) {
	body := readFixture(t, "canonical_match.txt")
	out := SecurityTxtValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		URL:      "https://example.org/.well-known/security.txt",
		Body:     body,
	}})
	if hasFinding(out.Findings, "SECTXT-007") {
		t.Error("did not expect SECTXT-007 when Canonical matches the fetched URL")
	}
}

func TestSecurityTxtValidator_ServedFromLegacyPath(t *testing.T) {
	body := readFixture(t, "canonical_match.txt")
	out := SecurityTxtValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		URL:      "https://example.org/.well-known/security.txt",
		RedirectChain: []string{
			"https://example.org/security.txt",
		},
		Body: body,
	}})
	if !hasFinding(out.Findings, "SECTXT-008") {
		t.Error("expected SECTXT-008 (served from legacy /security.txt)")
	}
}

func TestSecurityTxtValidator_MalformedLineAndUnknownField(t *testing.T) {
	body := readFixture(t, "malformed_and_unknown.txt")
	out := SecurityTxtValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		URL:      "https://example.org/.well-known/security.txt",
		Body:     body,
	}})
	if !hasFinding(out.Findings, "SECTXT-011") {
		t.Error("expected SECTXT-011 (unknown field)")
	}
	if !hasFinding(out.Findings, "SECTXT-012") {
		t.Error("expected SECTXT-012 (malformed field syntax)")
	}
}

func TestSecurityTxtValidator_ClearsignedDetected(t *testing.T) {
	body := readFixture(t, "clearsigned.txt")
	out := SecurityTxtValidator{}.Validate(Context{
		Result: scan.Result{
			Presence: scan.PresencePresent,
			URL:      "https://example.org/.well-known/security.txt",
			Body:     body,
		},
		Fetch: func(url string) (*scan.Result, error) {
			return &scan.Result{
				Presence: scan.PresencePresent,
				Body:     []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\nfakefakefake\n-----END PGP PUBLIC KEY BLOCK-----\n"),
			}, nil
		},
	})
	if !hasFinding(out.Findings, "SECTXT-009") {
		t.Error("expected SECTXT-009 (PGP signature present)")
	}
	if hasFinding(out.Findings, "SECTXT-010") {
		t.Error("did not expect SECTXT-010 when the referenced key is reachable and valid")
	}
	if out.Facts["has_signature"] != "true" || out.Facts["signature_type"] != "clearsign" {
		t.Errorf("signature facts = %+v", out.Facts)
	}
}

func TestSecurityTxtValidator_SignatureVerificationFailsWhenKeyUnreachable(t *testing.T) {
	body := readFixture(t, "clearsigned.txt")
	out := SecurityTxtValidator{}.Validate(Context{
		Result: scan.Result{
			Presence: scan.PresencePresent,
			URL:      "https://example.org/.well-known/security.txt",
			Body:     body,
		},
		Fetch: func(url string) (*scan.Result, error) {
			return &scan.Result{Presence: scan.PresenceAbsent}, nil
		},
	})
	if !hasFinding(out.Findings, "SECTXT-010") {
		t.Error("expected SECTXT-010 (signature verification failed: key unreachable)")
	}
	for _, f := range out.Findings {
		if f.ID == "SECTXT-010" && f.Severity != finding.SeverityHigh {
			t.Errorf("SECTXT-010 severity = %q, want high", f.Severity)
		}
	}
}

func TestSecurityTxtValidator_SignatureVerificationFailsWhenKeyInvalid(t *testing.T) {
	body := readFixture(t, "clearsigned.txt")
	out := SecurityTxtValidator{}.Validate(Context{
		Result: scan.Result{
			Presence: scan.PresencePresent,
			URL:      "https://example.org/.well-known/security.txt",
			Body:     body,
		},
		Fetch: func(url string) (*scan.Result, error) {
			return &scan.Result{Presence: scan.PresencePresent, Body: []byte("not a key")}, nil
		},
	})
	if !hasFinding(out.Findings, "SECTXT-010") {
		t.Error("expected SECTXT-010 (signature verification failed: not a valid key block)")
	}
}

func TestSecurityTxtValidator_NoAuxFetcherSkipsVerification(t *testing.T) {
	body := readFixture(t, "clearsigned.txt")
	out := SecurityTxtValidator{}.Validate(Context{
		Result: scan.Result{
			Presence: scan.PresencePresent,
			URL:      "https://example.org/.well-known/security.txt",
			Body:     body,
		},
		Fetch: nil,
	})
	if hasFinding(out.Findings, "SECTXT-010") {
		t.Error("did not expect SECTXT-010 when no AuxFetcher is available to verify")
	}
}

func TestSecurityTxtValidator_FactsIncludeContactAndPolicy(t *testing.T) {
	body := readFixture(t, "canonical_match.txt")
	out := SecurityTxtValidator{}.Validate(Context{Result: scan.Result{
		Presence: scan.PresencePresent,
		URL:      "https://example.org/.well-known/security.txt",
		Body:     body,
	}})
	if out.Facts["contact_count"] != "1" {
		t.Errorf("contact_count = %q, want 1", out.Facts["contact_count"])
	}
	if out.Facts["policy_present"] != "false" {
		t.Errorf("policy_present = %q, want false", out.Facts["policy_present"])
	}
}

func TestSecurityTxtValidator_RegisteredInLookup(t *testing.T) {
	v, ok := Lookup("security.txt")
	if !ok {
		t.Fatal("expected security.txt validator to be registered")
	}
	if v.Path() != "security.txt" {
		t.Errorf("Lookup returned validator for %q", v.Path())
	}
}
