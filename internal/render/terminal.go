package render

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/muesli/termenv"

	"github.com/harborproject/magpie/internal/banner"
	"github.com/harborproject/magpie/internal/compare"
	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/infer"
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
	colorBorder  = lipgloss.Color("6")
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

	if opts.ShowBanner {
		bannerStyle := base.Foreground(colorHeading)
		taglineStyle := base.Foreground(colorMuted).Italic(true)
		b.WriteString(bannerStyle.Render(banner.Bird + banner.Wordmark))
		b.WriteString("\n")
		b.WriteString(taglineStyle.Render(banner.Tagline) + "\n\n")
	}

	headerBox := base.
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorBorder).
		Padding(0, 1)
	headerLines := bold.Render("magpie") + " — " + bold.Render(rep.Domain)
	if !opts.NoTimestamps {
		headerLines += "\n" + muted.Render("scanned "+rep.ScannedAt.Format("2006-01-02 15:04:05 MST"))
	}
	b.WriteString(headerBox.Render(headerLines) + "\n\n")

	b.WriteString(heading.Render("WELL-KNOWN PATHS") + "\n")
	b.WriteString(renderPathsTable(renderer, rep.Paths, opts.Timing) + "\n\n")

	filtered := opts.Filter.Apply(rep.Findings)
	b.WriteString(heading.Render(fmt.Sprintf("FINDINGS (%d)", len(filtered))) + "\n")
	if len(filtered) == 0 {
		b.WriteString(muted.Render("  none") + "\n\n")
	} else {
		for _, group := range finding.GroupByCategory(filtered) {
			b.WriteString("  " + bold.Render(strings.ToUpper(string(group.Category))) + "\n")
			b.WriteString(renderFindingsTable(renderer, group.Findings) + "\n\n")
		}
	}

	b.WriteString(heading.Render("INFERENCE") + "\n")
	b.WriteString(renderInference(rep.Inference, base, muted) + "\n")

	if opts.Compare {
		if err := appendCompareSection(&b, renderer, rep, base, heading, muted); err != nil {
			return err
		}
	}

	_, err := w.Write([]byte(b.String()))
	return err
}

func renderPathsTable(renderer *lipgloss.Renderer, paths []report.PathResult, timing bool) string {
	base := renderer.NewStyle()
	headerStyle := base.Bold(true).Foreground(colorHeading)

	headers := []string{"PATH", "PRESENCE", "CONTENT-TYPE"}
	if timing {
		headers = append(headers, "TTFB", "TOTAL")
	}
	headers = append(headers, "SERVER")

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(base.Foreground(colorMuted)).
		BorderRow(false).
		Headers(headers...)

	for _, p := range paths {
		row := []string{"/.well-known/" + p.Path, string(p.Presence), p.ContentType}
		if timing {
			row = append(row, durMS(p.TTFB), durMS(p.Total))
		}
		server := p.Server
		if p.RedirectOffsiteTo != "" {
			server = strings.TrimSpace(server + " -> " + p.RedirectOffsiteTo)
		}
		row = append(row, server)
		t.Row(row...)
	}

	t.StyleFunc(func(row, col int) lipgloss.Style {
		if row == table.HeaderRow {
			return headerStyle
		}
		if row < 0 || row >= len(paths) {
			return base
		}
		if col == 1 {
			return base.Foreground(presenceColor(paths[row].Presence))
		}
		return base
	})

	return t.String()
}

func renderFindingsTable(renderer *lipgloss.Renderer, findings []finding.Finding) string {
	base := renderer.NewStyle()
	headerStyle := base.Bold(true).Foreground(colorHeading)

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(base.Foreground(colorMuted)).
		BorderRow(false).
		Headers("SEVERITY", "ID", "CONFIDENCE", "MESSAGE")

	for _, f := range findings {
		msg := f.Message
		if f.Evidence != "" {
			msg += "\nevidence: " + f.Evidence
		}
		t.Row(strings.ToUpper(string(f.Severity)), f.ID, string(f.Confidence), msg)
	}

	t.StyleFunc(func(row, col int) lipgloss.Style {
		if row == table.HeaderRow {
			return headerStyle
		}
		if row < 0 || row >= len(findings) {
			return base
		}
		if col == 0 {
			return base.Bold(true).Foreground(severityColor(findings[row].Severity))
		}
		if col == 3 {
			return base.Foreground(colorMuted)
		}
		return base
	})

	return t.String()
}

func renderInference(inf infer.Result, base, muted lipgloss.Style) string {
	var b strings.Builder
	wroteAny := false

	if inf.IdentityProvider != nil {
		fmt.Fprintf(&b, "  identity provider: %s (%s)\n", inf.IdentityProvider.Provider, inf.IdentityProvider.Issuer)
		wroteAny = true
	}
	for _, app := range inf.MobileApps {
		fmt.Fprintf(&b, "  mobile app (%s): %s\n", app.Platform, strings.Join(app.Identifiers, ", "))
		wroteAny = true
	}
	if inf.MailSecurity != nil && inf.MailSecurity.Configured {
		fmt.Fprintf(&b, "  mail security: mode=%s dns_activated=%t\n", inf.MailSecurity.Mode, inf.MailSecurity.DNSActivated)
		wroteAny = true
	}
	if inf.Matrix != nil {
		fmt.Fprintf(&b, "  matrix homeserver: %s (via %s)\n", inf.Matrix.Address, inf.Matrix.Source)
		wroteAny = true
	}
	if inf.ACME != nil && inf.ACME.Present {
		b.WriteString("  acme/cert automation: present\n")
		wroteAny = true
	}
	if inf.BugBountyProgram != nil {
		fmt.Fprintf(&b, "  bug bounty platform: %s (%s)\n", inf.BugBountyProgram.Platform, inf.BugBountyProgram.URL)
		wroteAny = true
	}
	if !wroteAny {
		b.WriteString(muted.Render("  nothing inferred") + "\n")
	}
	return b.String()
}

func appendCompareSection(b *strings.Builder, renderer *lipgloss.Renderer, rep report.Report, base, heading, muted lipgloss.Style) error {
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

	headerStyle := base.Bold(true).Foreground(colorHeading)
	rows := compare.Rows(corpus, present)

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(base.Foreground(colorMuted)).
		BorderRow(false).
		Headers("PATH", "PRESENT", "REFERENCE SAMPLE")

	for _, row := range rows {
		mark := "absent"
		if row.TargetPresent {
			mark = "present"
		}
		t.Row("/.well-known/"+row.Path, mark, fmt.Sprintf("~%d%% typically present", row.PercentPresent))
	}

	t.StyleFunc(func(row, col int) lipgloss.Style {
		if row == table.HeaderRow {
			return headerStyle
		}
		if row < 0 || row >= len(rows) {
			return base
		}
		if col == 1 {
			if rows[row].TargetPresent {
				return base.Foreground(colorPresent)
			}
			return base.Foreground(colorAbsent)
		}
		return base
	})

	b.WriteString(t.String() + "\n")
	return nil
}

func durMS(d time.Duration) string {
	return fmt.Sprintf("%dms", d.Milliseconds())
}
