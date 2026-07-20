package render

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/harborproject/magpie/internal/compare"
	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/report"
	"github.com/harborproject/magpie/internal/scan"
)

var (
	colorHigh    = lipgloss.Color("9")
	colorMedium  = lipgloss.Color("11")
	colorLow     = lipgloss.Color("14")
	colorInfo    = lipgloss.Color("245")
	colorPresent = lipgloss.Color("10")
	colorAbsent  = lipgloss.Color("245")
	colorSoft404 = lipgloss.Color("11")
	colorError   = lipgloss.Color("9")
	colorOffsite = lipgloss.Color("13")
	colorMuted   = lipgloss.Color("245")
	colorHeading = lipgloss.Color("6")
)

func severityColor(s finding.Severity) lipgloss.Color {
	switch s {
	case finding.SeverityHigh:
		return colorHigh
	case finding.SeverityMedium:
		return colorMedium
	case finding.SeverityLow:
		return colorLow
	default:
		return colorInfo
	}
}

func presenceColor(p scan.Presence) lipgloss.Color {
	switch p {
	case scan.PresencePresent:
		return colorPresent
	case scan.PresenceSoft404:
		return colorSoft404
	case scan.PresenceError:
		return colorError
	case scan.PresenceRedirectedOffsite:
		return colorOffsite
	default:
		return colorAbsent
	}
}

func Terminal(w io.Writer, rep report.Report, opts Options) error {
	renderer := lipgloss.NewRenderer(w)
	if opts.NoColor {
		renderer.SetColorProfile(termenv.Ascii)
	}

	base := renderer.NewStyle()
	bold := base.Bold(true)
	heading := base.Bold(true).Foreground(colorHeading)
	muted := base.Foreground(colorMuted)

	var b strings.Builder

	title := bold.Render("magpie") + " — " + bold.Render(rep.Domain)
	b.WriteString(title + "\n")
	if !opts.NoTimestamps {
		b.WriteString(muted.Render("scanned "+rep.ScannedAt.Format("2006-01-02 15:04:05 MST")) + "\n")
	}
	b.WriteString("\n")

	b.WriteString(heading.Render("WELL-KNOWN PATHS") + "\n")
	pathCol, presenceCol, ctCol := widestPath(rep.Paths), 18, 28
	for _, p := range rep.Paths {
		presenceStyle := base.Foreground(presenceColor(p.Presence))
		line := fmt.Sprintf("  %-*s  %s  %-*s",
			pathCol, "/.well-known/"+p.Path,
			presenceStyle.Render(fmt.Sprintf("%-*s", presenceCol, string(p.Presence))),
			ctCol, truncate(p.ContentType, ctCol),
		)
		if opts.Timing {
			line += fmt.Sprintf("  ttfb=%-8s total=%-8s", durMS(p.TTFB), durMS(p.Total))
		}
		if p.Server != "" {
			line += "  " + muted.Render(p.Server)
		}
		if p.RedirectOffsiteTo != "" {
			line += "  " + muted.Render("-> "+p.RedirectOffsiteTo)
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\n")

	filtered := opts.Filter.Apply(rep.Findings)
	b.WriteString(heading.Render(fmt.Sprintf("FINDINGS (%d)", len(filtered))) + "\n")
	if len(filtered) == 0 {
		b.WriteString(muted.Render("  none") + "\n")
	}
	for _, group := range finding.GroupByCategory(filtered) {
		b.WriteString("  " + bold.Render(strings.ToUpper(string(group.Category))) + "\n")
		for _, f := range group.Findings {
			sevStyle := base.Foreground(severityColor(f.Severity))
			b.WriteString(fmt.Sprintf("    [%s] %-6s %-8s %s\n",
				sevStyle.Render(strings.ToUpper(string(f.Severity))),
				f.ID, string(f.Confidence), f.Message))
			if f.Evidence != "" {
				b.WriteString(muted.Render("      evidence: "+f.Evidence) + "\n")
			}
		}
	}
	b.WriteString("\n")

	b.WriteString(heading.Render("INFERENCE") + "\n")
	inf := rep.Inference
	if inf.IdentityProvider != nil {
		b.WriteString(fmt.Sprintf("  identity provider: %s (%s)\n", inf.IdentityProvider.Provider, inf.IdentityProvider.Issuer))
	}
	for _, app := range inf.MobileApps {
		b.WriteString(fmt.Sprintf("  mobile app (%s): %s\n", app.Platform, strings.Join(app.Identifiers, ", ")))
	}
	if inf.MailSecurity != nil && inf.MailSecurity.Configured {
		b.WriteString(fmt.Sprintf("  mail security: mode=%s dns_activated=%t\n", inf.MailSecurity.Mode, inf.MailSecurity.DNSActivated))
	}
	if inf.Matrix != nil {
		b.WriteString(fmt.Sprintf("  matrix homeserver: %s (via %s)\n", inf.Matrix.Address, inf.Matrix.Source))
	}
	if inf.ACME != nil && inf.ACME.Present {
		b.WriteString("  acme/cert automation: present\n")
	}
	if inf.IdentityProvider == nil && len(inf.MobileApps) == 0 &&
		(inf.MailSecurity == nil || !inf.MailSecurity.Configured) &&
		inf.Matrix == nil && (inf.ACME == nil || !inf.ACME.Present) {
		b.WriteString(muted.Render("  nothing inferred") + "\n")
	}

	if opts.Compare {
		if err := appendCompareSection(&b, rep, base, heading, muted); err != nil {
			return err
		}
	}

	_, err := w.Write([]byte(b.String()))
	return err
}

func appendCompareSection(b *strings.Builder, rep report.Report, base, heading, muted lipgloss.Style) error {
	corpus, err := compare.Load()
	if err != nil {
		return err
	}

	present := map[string]bool{}
	for _, p := range rep.PresentPaths() {
		present[p.Path] = true
	}

	b.WriteString(heading.Render("COMPARE TO REFERENCE CORPUS") + "\n")
	b.WriteString(muted.Render("  "+corpus.Description) + "\n\n")

	pathCol := len("path")
	for _, row := range compare.Rows(corpus, present) {
		if l := len("/.well-known/" + row.Path); l > pathCol {
			pathCol = l
		}
	}
	for _, row := range compare.Rows(corpus, present) {
		mark := "absent "
		style := base.Foreground(colorAbsent)
		if row.TargetPresent {
			mark = "present"
			style = base.Foreground(colorPresent)
		}
		fmt.Fprintf(b, "  %-*s  %s  typically present in ~%d%% of the reference sample\n",
			pathCol, "/.well-known/"+row.Path, style.Render(mark), row.PercentPresent)
	}
	b.WriteString("\n")
	return nil
}

func widestPath(paths []report.PathResult) int {
	max := len("path")
	for _, p := range paths {
		if l := len("/.well-known/" + p.Path); l > max {
			max = l
		}
	}
	return max
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func durMS(d time.Duration) string {
	return fmt.Sprintf("%dms", d.Milliseconds())
}
