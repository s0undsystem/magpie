package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/report"
)

func Markdown(w io.Writer, rep report.Report, opts Options) error {
	var b strings.Builder

	fmt.Fprintf(&b, "# magpie report: %s\n\n", rep.Domain)
	if !opts.NoTimestamps {
		fmt.Fprintf(&b, "_Scanned %s_\n\n", rep.ScannedAt.Format("2006-01-02 15:04:05 MST"))
	}

	b.WriteString("## Well-known paths\n\n")
	b.WriteString("| Path | Presence | Content-Type |")
	if opts.Timing {
		b.WriteString(" TTFB | Total |")
	}
	b.WriteString("\n|---|---|---|")
	if opts.Timing {
		b.WriteString("---|---|")
	}
	b.WriteString("\n")
	for _, p := range rep.Paths {
		fmt.Fprintf(&b, "| `/.well-known/%s` | %s | %s |", p.Path, p.Presence, mdEscape(p.ContentType))
		if opts.Timing {
			fmt.Fprintf(&b, " %dms | %dms |", p.TTFB.Milliseconds(), p.Total.Milliseconds())
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	filtered := opts.Filter.Apply(rep.Findings)
	fmt.Fprintf(&b, "## Findings (%d)\n\n", len(filtered))
	if len(filtered) == 0 {
		b.WriteString("None.\n\n")
	}
	for _, group := range finding.GroupByCategory(filtered) {
		fmt.Fprintf(&b, "### %s\n\n", strings.ToUpper(string(group.Category)))
		b.WriteString("| ID | Severity | Confidence | Message | Evidence |\n|---|---|---|---|---|\n")
		for _, f := range group.Findings {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				f.ID, f.Severity, f.Confidence, mdEscape(f.Message), mdEscape(f.Evidence))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Inference\n\n")
	inf := rep.Inference
	wroteAny := false
	if inf.IdentityProvider != nil {
		fmt.Fprintf(&b, "- **Identity provider**: %s (`%s`)\n", inf.IdentityProvider.Provider, inf.IdentityProvider.Issuer)
		wroteAny = true
	}
	for _, app := range inf.MobileApps {
		fmt.Fprintf(&b, "- **Mobile app (%s)**: %s\n", app.Platform, strings.Join(app.Identifiers, ", "))
		wroteAny = true
	}
	if inf.MailSecurity != nil && inf.MailSecurity.Configured {
		fmt.Fprintf(&b, "- **Mail security**: mode=%s, dns_activated=%t\n", inf.MailSecurity.Mode, inf.MailSecurity.DNSActivated)
		wroteAny = true
	}
	if inf.Matrix != nil {
		fmt.Fprintf(&b, "- **Matrix homeserver**: %s (via %s)\n", inf.Matrix.Address, inf.Matrix.Source)
		wroteAny = true
	}
	if inf.ACME != nil && inf.ACME.Present {
		b.WriteString("- **ACME/cert automation**: present\n")
		wroteAny = true
	}
	if inf.BugBountyProgram != nil {
		fmt.Fprintf(&b, "- **Bug bounty platform**: %s (`%s`)\n", inf.BugBountyProgram.Platform, inf.BugBountyProgram.URL)
		wroteAny = true
	}
	if !wroteAny {
		b.WriteString("Nothing inferred.\n")
	}

	_, err := w.Write([]byte(b.String()))
	return err
}

func mdEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}
