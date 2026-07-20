package validate

import (
	"testing"

	"github.com/s0undsystem/magpie/internal/scan"
)

func TestChangePasswordValidator_Path(t *testing.T) {
	if got := (ChangePasswordValidator{}).Path(); got != "change-password" {
		t.Errorf("Path() = %q", got)
	}
}

func TestChangePasswordValidator_HTMLPresentNoFinding(t *testing.T) {
	out := ChangePasswordValidator{}.Validate(Context{Result: scan.Result{
		Presence:    scan.PresencePresent,
		ContentType: "text/html; charset=utf-8",
	}})
	if len(out.Findings) != 0 {
		t.Errorf("expected no findings for HTML 200, got %+v", out.Findings)
	}
}

func TestChangePasswordValidator_NonHTMLFlagged(t *testing.T) {
	out := ChangePasswordValidator{}.Validate(Context{Result: scan.Result{
		Presence:    scan.PresencePresent,
		ContentType: "application/json",
	}})
	if !hasFinding(out.Findings, "CHPW-001") {
		t.Error("expected CHPW-001 (non-HTML content type)")
	}
}

func TestChangePasswordValidator_RedirectedFact(t *testing.T) {
	out := ChangePasswordValidator{}.Validate(Context{Result: scan.Result{
		Presence:      scan.PresenceAbsent,
		RedirectChain: []string{"https://example.org/account/security/password"},
	}})
	if out.Facts["redirected"] != "true" {
		t.Errorf("redirected fact = %q, want true", out.Facts["redirected"])
	}
}

func TestChangePasswordValidator_AbsentNoContentFinding(t *testing.T) {
	out := ChangePasswordValidator{}.Validate(Context{Result: scan.Result{Presence: scan.PresenceAbsent}})
	if hasFinding(out.Findings, "CHPW-001") {
		t.Error("did not expect CHPW-001 when the path is simply absent")
	}
}
