package correlate

import (
	"testing"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
)

func findByID(findings []finding.Finding, id string) *finding.Finding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}

func countByID(findings []finding.Finding, id string) int {
	n := 0
	for _, f := range findings {
		if f.ID == id {
			n++
		}
	}
	return n
}

func TestEngineLoadsAllExpectedRuleIDs(t *testing.T) {
	want := []string{
		"CORR-001", "CORR-002", "CORR-003", "CORR-004", "CORR-005", "CORR-006", "CORR-007", "CORR-008",
		"CORR-009", "CORR-010", "CORR-011", "CORR-012", "CORR-013", "CORR-014", "CORR-015", "CORR-016",
		"CORR-017", "CORR-018", "CORR-019", "CORR-020", "CORR-021", "CORR-022", "CORR-023", "CORR-024", "CORR-025",
	}
	e := NewEngine()
	for _, id := range want {
		if _, ok := e.Rule(id); !ok {
			t.Errorf("expected rule %s to be loaded", id)
		}
	}
	if len(e.Rules()) != len(want) {
		t.Errorf("loaded %d rules, want %d", len(e.Rules()), len(want))
	}
}

func TestEngineRulesSortedByID(t *testing.T) {
	e := NewEngine()
	rules := e.Rules()
	for i := 1; i < len(rules); i++ {
		if rules[i-1].ID >= rules[i].ID {
			t.Fatalf("rules not sorted: %s before %s", rules[i-1].ID, rules[i].ID)
		}
	}
}

func TestCORR001_OIDCPresentSecurityTxtAbsent(t *testing.T) {
	s := snap(map[string]DocFacts{
		"openid-configuration": doc(scan.PresencePresent, nil),
		"security.txt":         doc(scan.PresenceAbsent, nil),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-001") == nil {
		t.Error("expected CORR-001")
	}
}

func TestCORR001_DoesNotFireWhenSecurityTxtPresent(t *testing.T) {
	s := snap(map[string]DocFacts{
		"openid-configuration": doc(scan.PresencePresent, nil),
		"security.txt":         doc(scan.PresencePresent, map[string]string{}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-001") != nil {
		t.Error("did not expect CORR-001 when security.txt is present")
	}
}

func TestCORR002_MobileWithoutScopeMention(t *testing.T) {
	s := snap(map[string]DocFacts{
		"assetlinks.json": doc(scan.PresencePresent, nil),
		"security.txt":    doc(scan.PresencePresent, map[string]string{"mentions_mobile_scope": "false"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-002") == nil {
		t.Error("expected CORR-002")
	}
}

func TestCORR002_DoesNotFireWhenScopeMentioned(t *testing.T) {
	s := snap(map[string]DocFacts{
		"assetlinks.json": doc(scan.PresencePresent, nil),
		"security.txt":    doc(scan.PresencePresent, map[string]string{"mentions_mobile_scope": "true"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-002") != nil {
		t.Error("did not expect CORR-002 when mobile scope is mentioned")
	}
}

func TestCORR003_ExpiresWithin30Days(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"expires_days_remaining": "10"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	f := findByID(got, "CORR-003")
	if f == nil {
		t.Fatal("expected CORR-003")
	}
	if f.Evidence != "10 day(s) remaining" {
		t.Errorf("evidence = %q", f.Evidence)
	}
}

func TestCORR004_ExpiresInPast(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"expires_days_remaining": "-5"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-004") == nil {
		t.Error("expected CORR-004")
	}
	if findByID(got, "CORR-003") != nil {
		t.Error("did not expect CORR-003 (within 30 days) once already expired")
	}
}

func TestCORR005_TestingModeOldPolicyID(t *testing.T) {
	s := snap(map[string]DocFacts{
		"mta-sts.txt": doc(scan.PresencePresent, map[string]string{
			"mode": "testing", "mta_sts_dns_txt_id_age_days": "120",
		}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-005") == nil {
		t.Error("expected CORR-005")
	}
}

func TestCORR005_DoesNotFireWhenIDRecent(t *testing.T) {
	s := snap(map[string]DocFacts{
		"mta-sts.txt": doc(scan.PresencePresent, map[string]string{
			"mode": "testing", "mta_sts_dns_txt_id_age_days": "5",
		}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-005") != nil {
		t.Error("did not expect CORR-005 for a recent policy id")
	}
}

func TestCORR006_ChangePasswordSoft404(t *testing.T) {
	s := snap(map[string]DocFacts{"change-password": doc(scan.PresenceSoft404, nil)})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-006") == nil {
		t.Error("expected CORR-006")
	}
}

func TestCORR007_OneFindingPerOffsiteRedirect(t *testing.T) {
	s := snap(map[string]DocFacts{
		"change-password": {Presence: scan.PresenceRedirectedOffsite, RedirectOffsiteTo: "other.example.net"},
		"webfinger":       {Presence: scan.PresenceRedirectedOffsite, RedirectOffsiteTo: "another.example.net"},
		"security.txt":    doc(scan.PresencePresent, nil),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if countByID(got, "CORR-007") != 2 {
		t.Errorf("expected 2 CORR-007 findings, got %d", countByID(got, "CORR-007"))
	}
}

func TestCORR008_NoSecurityTxt(t *testing.T) {
	s := snap(map[string]DocFacts{"security.txt": doc(scan.PresenceAbsent, nil)})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-008") == nil {
		t.Error("expected CORR-008")
	}
}

func TestCORR009_ContactFormOnly(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"contact_form_only": "true", "contact_values": "https://example.org/report"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-009") == nil {
		t.Error("expected CORR-009")
	}
}

func TestCORR010_ExternalContactDomain(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"contact_external_domain": "bugcrowd.com"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	f := findByID(got, "CORR-010")
	if f == nil {
		t.Fatal("expected CORR-010")
	}
	if f.Evidence != "bugcrowd.com" {
		t.Errorf("evidence = %q", f.Evidence)
	}
}

func TestCORR011_NoPolicy(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"policy_present": "false"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-011") == nil {
		t.Error("expected CORR-011")
	}
}

func TestCORR012_NoPreferredLanguages(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"preferred_languages_present": "false"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-012") == nil {
		t.Error("expected CORR-012")
	}
}

func TestCORR013_EncryptionKeyUnreachable(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"encryption_key_reachable": "false", "encryption_url": "https://example.org/key.txt"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-013") == nil {
		t.Error("expected CORR-013")
	}
}

func TestCORR013_ViaSectxtFindingExists(t *testing.T) {
	d := doc(scan.PresencePresent, map[string]string{})
	d.Findings = []finding.Finding{{ID: "SECTXT-010"}}
	s := snap(map[string]DocFacts{"security.txt": d})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-013") == nil {
		t.Error("expected CORR-013 when SECTXT-010 fired")
	}
}

func TestCORR014_AcknowledgmentsWithoutPolicy(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"policy_present": "false", "acknowledgments_present": "true"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-014") == nil {
		t.Error("expected CORR-014")
	}
}

func TestCORR014_HiringWithoutPolicy(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"policy_present": "false", "hiring_present": "true"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-014") == nil {
		t.Error("expected CORR-014")
	}
}

func TestCORR015_DuplicateExpires(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"expires_duplicate": "true", "field_after_signature": "false"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	f := findByID(got, "CORR-015")
	if f == nil {
		t.Fatal("expected CORR-015")
	}
	if f.Confidence != finding.ConfidenceCertain {
		t.Errorf("confidence = %q, want certain", f.Confidence)
	}
}

func TestCORR015_FieldAfterSignature(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{"expires_duplicate": "false", "field_after_signature": "true"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-015") == nil {
		t.Error("expected CORR-015")
	}
}

func TestCORR016_IssuerOriginMismatch(t *testing.T) {
	s := snap(map[string]DocFacts{
		"openid-configuration": doc(scan.PresencePresent, map[string]string{"issuer_matches_origin": "false", "issuer": "https://elsewhere.example"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	f := findByID(got, "CORR-016")
	if f == nil {
		t.Fatal("expected CORR-016")
	}
	if f.Confidence != finding.ConfidenceCertain {
		t.Errorf("confidence = %q, want certain", f.Confidence)
	}
}

func TestCORR017_RequestURIWithoutRegistration(t *testing.T) {
	s := snap(map[string]DocFacts{
		"openid-configuration": doc(scan.PresencePresent, map[string]string{
			"request_uri_parameter_supported": "true", "require_request_uri_registration": "false",
		}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-017") == nil {
		t.Error("expected CORR-017")
	}
}

func TestCORR018_JWKSOffsite(t *testing.T) {
	s := snap(map[string]DocFacts{
		"openid-configuration": doc(scan.PresencePresent, map[string]string{"jwks_uri_offsite": "true"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-018") == nil {
		t.Error("expected CORR-018")
	}
}

func TestCORR019_PlaintextEndpoint(t *testing.T) {
	s := snap(map[string]DocFacts{
		"openid-configuration": doc(scan.PresencePresent, map[string]string{"endpoint_urls": "http://example.org/token"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	f := findByID(got, "CORR-019")
	if f == nil {
		t.Fatal("expected CORR-019")
	}
	if f.Confidence != finding.ConfidenceCertain {
		t.Errorf("confidence = %q, want certain", f.Confidence)
	}
}

func TestCORR019_DoesNotFireForHTTPSOnly(t *testing.T) {
	s := snap(map[string]DocFacts{
		"openid-configuration": doc(scan.PresencePresent, map[string]string{"endpoint_urls": "https://example.org/token"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-019") != nil {
		t.Error("did not expect CORR-019 when every endpoint is https")
	}
}

func TestCORR020_IssuerConflict(t *testing.T) {
	s := snap(map[string]DocFacts{
		"openid-configuration":       doc(scan.PresencePresent, map[string]string{"issuer": "https://a.example.org"}),
		"oauth-authorization-server": doc(scan.PresencePresent, map[string]string{"issuer": "https://b.example.org"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-020") == nil {
		t.Error("expected CORR-020")
	}
}

func TestCORR020_DoesNotFireWhenIssuersMatch(t *testing.T) {
	s := snap(map[string]DocFacts{
		"openid-configuration":       doc(scan.PresencePresent, map[string]string{"issuer": "https://a.example.org"}),
		"oauth-authorization-server": doc(scan.PresencePresent, map[string]string{"issuer": "https://a.example.org"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-020") != nil {
		t.Error("did not expect CORR-020 when issuers agree")
	}
}

func TestCORR021_DNSTXTAbsent(t *testing.T) {
	s := snap(map[string]DocFacts{
		"mta-sts.txt": doc(scan.PresencePresent, map[string]string{"mta_sts_dns_txt_present": "false"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-021") == nil {
		t.Error("expected CORR-021")
	}
}

func TestCORR022_MXMismatch(t *testing.T) {
	s := snap(map[string]DocFacts{
		"mta-sts.txt": doc(scan.PresencePresent, map[string]string{"mx_patterns": "mail.example.org"}),
	})
	opts := EvalOptions{LookupMX: func(host string) ([]string, error) {
		return []string{"unrelated.otherhost.net"}, nil
	}}
	got := NewEngine().Evaluate(s, opts)
	if findByID(got, "CORR-022") == nil {
		t.Error("expected CORR-022")
	}
}

func TestCORR022_NoFindingWhenCovered(t *testing.T) {
	s := snap(map[string]DocFacts{
		"mta-sts.txt": doc(scan.PresencePresent, map[string]string{"mx_patterns": "*.example.org"}),
	})
	opts := EvalOptions{LookupMX: func(host string) ([]string, error) {
		return []string{"mail.example.org"}, nil
	}}
	got := NewEngine().Evaluate(s, opts)
	if findByID(got, "CORR-022") != nil {
		t.Error("did not expect CORR-022 when the wildcard pattern covers the MX host")
	}
}

func TestCORR022_NoLookupMXNoFinding(t *testing.T) {
	s := snap(map[string]DocFacts{
		"mta-sts.txt": doc(scan.PresencePresent, map[string]string{"mx_patterns": "mail.example.org"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-022") != nil {
		t.Error("did not expect CORR-022 when DNS lookups are disabled")
	}
}

func TestCORR023_AcmeChallengePresent(t *testing.T) {
	s := snap(map[string]DocFacts{"acme-challenge": doc(scan.PresencePresent, nil)})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-023") == nil {
		t.Error("expected CORR-023")
	}
}

func TestCORR024_GenericDisagreement(t *testing.T) {
	s := snap(map[string]DocFacts{
		"apple-app-site-association": doc(scan.PresencePresent, map[string]string{"organization_name": "Acme Corp"}),
		"assetlinks.json":            doc(scan.PresencePresent, map[string]string{"organization_name": "Acme Corporation"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-024") == nil {
		t.Error("expected CORR-024")
	}
}

func TestCORR024_ExcludesOIDCOAuthIssuerPair(t *testing.T) {
	// CORR-020 owns the openid-configuration/oauth-authorization-server
	// issuer comparison; CORR-024 must not also fire for it.
	s := snap(map[string]DocFacts{
		"openid-configuration":       doc(scan.PresencePresent, map[string]string{"issuer": "https://a.example.org"}),
		"oauth-authorization-server": doc(scan.PresencePresent, map[string]string{"issuer": "https://b.example.org"}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-024") != nil {
		t.Error("did not expect CORR-024 to duplicate CORR-020's issuer comparison")
	}
}

func TestCORR025_ThreeCleanDocsNoSecurityTxt(t *testing.T) {
	s := snap(map[string]DocFacts{
		"assetlinks.json":            doc(scan.PresencePresent, nil),
		"apple-app-site-association": doc(scan.PresencePresent, nil),
		"webfinger":                  doc(scan.PresencePresent, nil),
		"security.txt":               doc(scan.PresenceAbsent, nil),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-025") == nil {
		t.Error("expected CORR-025")
	}
}

func TestCORR025_DoesNotFireUnderThreeClean(t *testing.T) {
	s := snap(map[string]DocFacts{
		"assetlinks.json": doc(scan.PresencePresent, nil),
		"security.txt":    doc(scan.PresenceAbsent, nil),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if findByID(got, "CORR-025") != nil {
		t.Error("did not expect CORR-025 with fewer than 3 clean docs")
	}
}

func TestCleanBaselineFiresNothing(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresencePresent, map[string]string{
			"policy_present": "true", "preferred_languages_present": "true",
			"acknowledgments_present": "false", "hiring_present": "false",
			"expires_days_remaining": "180", "contact_form_only": "false",
			"mentions_mobile_scope": "true",
		}),
	})
	got := NewEngine().Evaluate(s, EvalOptions{})
	if len(got) != 0 {
		t.Errorf("expected a clean baseline to produce no findings, got %+v", got)
	}
}

func TestLoadOverlayOverridesSeverity(t *testing.T) {
	e := NewEngine()
	before, _ := e.Rule("CORR-008")
	if before.Severity != finding.SeverityMedium {
		t.Fatalf("precondition failed: CORR-008 default severity = %q", before.Severity)
	}

	overlay := []byte(`[{"id":"CORR-008","severity":"high","confidence":"inferred","category":"disclosure","message":"overridden","when":{"presence":{"path":"security.txt","in":["absent"]}}}]`)
	if err := e.LoadOverlay(overlay); err != nil {
		t.Fatal(err)
	}
	after, _ := e.Rule("CORR-008")
	if after.Severity != finding.SeverityHigh {
		t.Errorf("after overlay, severity = %q, want high", after.Severity)
	}
	if len(e.Rules()) != 25 {
		t.Errorf("overlay overriding an existing ID should not change the rule count, got %d", len(e.Rules()))
	}
}

func TestLoadOverlayAppendsNewRule(t *testing.T) {
	e := NewEngine()
	overlay := []byte(`[{"id":"CORR-900","severity":"info","confidence":"inferred","category":"hygiene","message":"custom community rule","when":{"presence":{"path":"security.txt","in":["present"]}}}]`)
	if err := e.LoadOverlay(overlay); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Rule("CORR-900"); !ok {
		t.Error("expected CORR-900 to be appended")
	}
	if len(e.Rules()) != 26 {
		t.Errorf("expected 26 rules after appending one, got %d", len(e.Rules()))
	}
}

func TestLoadOverlayInvalidJSON(t *testing.T) {
	e := NewEngine()
	if err := e.LoadOverlay([]byte("not json")); err == nil {
		t.Error("expected an error for invalid overlay JSON")
	}
}

func TestEvaluateOrderIsDeterministic(t *testing.T) {
	s := snap(map[string]DocFacts{
		"security.txt": doc(scan.PresenceAbsent, nil),
	})
	e := NewEngine()
	a := e.Evaluate(s, EvalOptions{})
	b := e.Evaluate(s, EvalOptions{})
	if len(a) != len(b) {
		t.Fatalf("finding counts differ across runs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("finding order differs at %d: %s vs %s", i, a[i].ID, b[i].ID)
		}
	}
}
