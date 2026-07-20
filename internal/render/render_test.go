package render

import (
	"time"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/infer"
	"github.com/harborproject/magpie/internal/report"
	"github.com/harborproject/magpie/internal/scan"
)

func fixtureReport() report.Report {
	return report.Report{
		SchemaVersion: report.SchemaVersion,
		Domain:        "example.org",
		ScannedAt:     time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		Control:       scan.Control{StatusCode: 404, ContentType: "text/html"},
		Paths: []report.PathResult{
			{Path: "security.txt", URL: "https://example.org/.well-known/security.txt", Presence: scan.PresencePresent, StatusCode: 200, ContentType: "text/plain", TTFB: 12 * time.Millisecond, Total: 34 * time.Millisecond},
			{Path: "webfinger", URL: "https://example.org/.well-known/webfinger", Presence: scan.PresenceAbsent, StatusCode: 404, ContentType: "text/html"},
		},
		Findings: []finding.Finding{
			{ID: "SECTXT-004", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain, Category: finding.CategoryDisclosure, Message: "security.txt's Expires date is in the past.", Evidence: "expired 3 day(s) ago"},
			{ID: "CORR-011", Severity: finding.SeverityLow, Confidence: finding.ConfidenceInferred, Category: finding.CategoryDisclosure, Message: "Contact published without rules of engagement."},
		},
		Inference: infer.Result{
			IdentityProvider: &infer.IdentityProvider{Provider: "Okta", Issuer: "https://example.okta.com"},
			MailSecurity:     &infer.MailSecurity{Configured: true, Mode: "enforce", DNSActivated: true},
		},
	}
}
