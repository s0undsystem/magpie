package validate

import (
	"strconv"
	"strings"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
)

func init() { Register(ChangePasswordValidator{}) }

// ChangePasswordValidator validates /.well-known/change-password. Per the
// convention, a well-behaved host either redirects the request or returns
// 200 with an HTML landing page; the absent/soft404-while-advertised case
// is a cross-document concern handled by the correlation engine (CORR-006),
// not this validator.
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
