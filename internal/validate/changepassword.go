package validate

import (
	"strconv"
	"strings"

	"github.com/harborproject/magpie/internal/explain"
	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
)

func init() {
	Register(ChangePasswordValidator{})

	explain.Register(explain.Doc{
		ID: "CHPW-001", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain, Category: finding.CategoryHygiene,
		Message: "change-password returned 200 but the content type is not HTML.", SpecRef: "W3C well-known change-password",
		Explanation: "The change-password convention exists so password managers can deep-link users straight into an account's password-change flow, which only works if the response is an HTML landing page (or a redirect to one). A 200 response in another content type usually means the path is serving something else, not an actual password-change UI. Remediation: serve an HTML page (or redirect) at /.well-known/change-password.",
	})
}

type ChangePasswordValidator struct{}

func (ChangePasswordValidator) Path() string { return "change-password" }

func (ChangePasswordValidator) Validate(ctx Context) Output {
	out := Output{Facts: Facts{}}
	r := ctx.Result

	out.Facts["redirected"] = strconv.FormatBool(len(r.RedirectChain) > 0)

	if r.Presence != scan.PresencePresent {
		return out
	}

	if !strings.Contains(strings.ToLower(baseContentType(r.ContentType)), "html") {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "CHPW-001", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryHygiene,
			Message:  "change-password returned 200 but the content type is not HTML.",
			Evidence: r.ContentType, SpecRef: "W3C well-known change-password",
		})
	}

	return out
}
