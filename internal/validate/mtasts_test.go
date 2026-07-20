package validate

import (
	"testing"

	"github.com/harborproject/magpie/internal/scan"
)

func mtastsResult(body string) scan.Result {
	return scan.Result{Presence: scan.PresencePresent, URL: "https://example.org/.well-known/mta-sts.txt", Body: []byte(body)}
}

func TestMTASTSValidator_Path(t *testing.T) {
	if got := (MTASTSValidator{}).Path(); got != "mta-sts.txt" {
		t.Errorf("Path() = %q", got)
	}
}

func TestMTASTSValidator_EnforceModeClean(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmx: mail.example.org\nmax_age: 604800\n"
	out := MTASTSValidator{}.Validate(Context{Result: mtastsResult(body)})
	if hasFinding(out.Findings, "MTASTS-001") || hasFinding(out.Findings, "MTASTS-002") || hasFinding(out.Findings, "MTASTS-003") {
		t.Errorf("unexpected mode findings: %+v", out.Findings)
	}
	if out.Facts["mode"] != "enforce" {
		t.Errorf("mode fact = %q", out.Facts["mode"])
	}
	if out.Facts["mx_count"] != "1" {
		t.Errorf("mx_count fact = %q", out.Facts["mx_count"])
	}
}

func TestMTASTSValidator_TestingMode(t *testing.T) {
	body := "version: STSv1\nmode: testing\nmx: mail.example.org\nmax_age: 604800\n"
	out := MTASTSValidator{}.Validate(Context{Result: mtastsResult(body)})
	if !hasFinding(out.Findings, "MTASTS-001") {
		t.Error("expected MTASTS-001 (testing mode)")
	}
}

func TestMTASTSValidator_NoneMode(t *testing.T) {
	body := "version: STSv1\nmode: none\nmax_age: 604800\n"
	out := MTASTSValidator{}.Validate(Context{Result: mtastsResult(body)})
	if !hasFinding(out.Findings, "MTASTS-002") {
		t.Error("expected MTASTS-002 (none mode)")
	}
}

func TestMTASTSValidator_InvalidMode(t *testing.T) {
	body := "version: STSv1\nmode: bogus\nmax_age: 604800\nmx: mail.example.org\n"
	out := MTASTSValidator{}.Validate(Context{Result: mtastsResult(body)})
	if !hasFinding(out.Findings, "MTASTS-003") {
		t.Error("expected MTASTS-003 (invalid mode)")
	}
}

func TestMTASTSValidator_BadMaxAge(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmx: mail.example.org\nmax_age: not-a-number\n"
	out := MTASTSValidator{}.Validate(Context{Result: mtastsResult(body)})
	if !hasFinding(out.Findings, "MTASTS-004") {
		t.Error("expected MTASTS-004 (bad max_age)")
	}
}

func TestMTASTSValidator_MaxAgeTooLarge(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmx: mail.example.org\nmax_age: 99999999\n"
	out := MTASTSValidator{}.Validate(Context{Result: mtastsResult(body)})
	if !hasFinding(out.Findings, "MTASTS-004") {
		t.Error("expected MTASTS-004 (max_age out of range)")
	}
}

func TestMTASTSValidator_NoMX(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmax_age: 604800\n"
	out := MTASTSValidator{}.Validate(Context{Result: mtastsResult(body)})
	if !hasFinding(out.Findings, "MTASTS-005") {
		t.Error("expected MTASTS-005 (no mx entries)")
	}
}

func TestMTASTSValidator_UnsupportedVersion(t *testing.T) {
	body := "version: STSv2\nmode: enforce\nmx: mail.example.org\nmax_age: 604800\n"
	out := MTASTSValidator{}.Validate(Context{Result: mtastsResult(body)})
	if !hasFinding(out.Findings, "MTASTS-007") {
		t.Error("expected MTASTS-007 (unsupported version)")
	}
}

func TestMTASTSValidator_DNSRecordWellFormed(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmx: mail.example.org\nmax_age: 604800\n"
	out := MTASTSValidator{}.Validate(Context{
		Host:   "example.org",
		Result: mtastsResult(body),
		LookupTXT: func(name string) ([]string, error) {
			if name != "_mta-sts.example.org" {
				t.Errorf("LookupTXT called with %q", name)
			}
			return []string{"v=STSv1; id=20250101000000Z"}, nil
		},
	})
	if hasFinding(out.Findings, "MTASTS-006") {
		t.Error("did not expect MTASTS-006 for a well-formed record")
	}
	if out.Facts["mta_sts_dns_txt_present"] != "true" || out.Facts["mta_sts_dns_txt_id"] != "20250101000000Z" {
		t.Errorf("dns facts = %+v", out.Facts)
	}
}

func TestMTASTSValidator_DNSRecordMalformed(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmx: mail.example.org\nmax_age: 604800\n"
	out := MTASTSValidator{}.Validate(Context{
		Host:   "example.org",
		Result: mtastsResult(body),
		LookupTXT: func(name string) ([]string, error) {
			return []string{"garbage record"}, nil
		},
	})
	if !hasFinding(out.Findings, "MTASTS-006") {
		t.Error("expected MTASTS-006 for a malformed DNS TXT record")
	}
}

func TestMTASTSValidator_DNSRecordAbsent(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmx: mail.example.org\nmax_age: 604800\n"
	out := MTASTSValidator{}.Validate(Context{
		Host:   "example.org",
		Result: mtastsResult(body),
		LookupTXT: func(name string) ([]string, error) {
			return nil, nil
		},
	})
	if out.Facts["mta_sts_dns_txt_present"] != "false" {
		t.Errorf("mta_sts_dns_txt_present = %q, want false", out.Facts["mta_sts_dns_txt_present"])
	}
	if hasFinding(out.Findings, "MTASTS-006") {
		t.Error("an entirely absent record is not malformed; that's a correlation-layer concern")
	}
}
