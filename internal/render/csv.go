package render

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/report"
)

var csvHeader = []string{
	"domain", "scanned_at", "paths_present",
	"findings_high", "findings_medium", "findings_low", "findings_info",
	"identity_provider", "mail_security_mode", "mail_dns_activated",
	"mobile_apps", "matrix_homeserver", "acme_present",
}

func CSV(w io.Writer, reports []report.Report, opts Options) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, rep := range reports {
		if err := cw.Write(csvRow(rep, opts)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func csvRow(rep report.Report, opts Options) []string {
	filtered := opts.Filter.Apply(rep.Findings)
	counts := map[finding.Severity]int{}
	for _, f := range filtered {
		counts[f.Severity]++
	}

	scannedAt := ""
	if !opts.NoTimestamps {
		scannedAt = rep.ScannedAt.Format("2006-01-02T15:04:05Z07:00")
	}

	inf := rep.Inference
	identityProvider := ""
	if inf.IdentityProvider != nil {
		identityProvider = inf.IdentityProvider.Provider
	}
	mailMode, mailDNS := "", ""
	if inf.MailSecurity != nil && inf.MailSecurity.Configured {
		mailMode = inf.MailSecurity.Mode
		mailDNS = strconv.FormatBool(inf.MailSecurity.DNSActivated)
	}
	var mobileParts []string
	for _, app := range inf.MobileApps {
		mobileParts = append(mobileParts, app.Platform+":"+strings.Join(app.Identifiers, "+"))
	}
	matrixHomeserver := ""
	if inf.Matrix != nil {
		matrixHomeserver = inf.Matrix.Address
	}
	acmePresent := "false"
	if inf.ACME != nil && inf.ACME.Present {
		acmePresent = "true"
	}

	return []string{
		rep.Domain,
		scannedAt,
		strconv.Itoa(len(rep.PresentPaths())),
		strconv.Itoa(counts[finding.SeverityHigh]),
		strconv.Itoa(counts[finding.SeverityMedium]),
		strconv.Itoa(counts[finding.SeverityLow]),
		strconv.Itoa(counts[finding.SeverityInfo]),
		identityProvider,
		mailMode,
		mailDNS,
		strings.Join(mobileParts, ";"),
		matrixHomeserver,
		acmePresent,
	}
}
