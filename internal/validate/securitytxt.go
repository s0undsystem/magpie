package validate

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/harborproject/magpie/internal/domainutil"
	"github.com/harborproject/magpie/internal/explain"
	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
)

func init() {
	Register(SecurityTxtValidator{})

	explain.Register(explain.Doc{
		ID: "SECTXT-001", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain, Category: finding.CategoryDisclosure,
		Message: "security.txt is missing the required Contact field.", SpecRef: "RFC 9116 §2.5.3",
		Explanation: "Contact is the one field RFC 9116 requires alongside Expires: without it, a security.txt file exists but gives a researcher no way to actually reach anyone. Remediation: add at least one Contact field with a mailto:, tel:, or https: value.",
	})
	explain.Register(explain.Doc{
		ID: "SECTXT-002", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain, Category: finding.CategoryDisclosure,
		Message: "security.txt is missing the required Expires field.", SpecRef: "RFC 9116 §2.5.5",
		Explanation: "Expires lets clients and researchers know how fresh the file is and when to stop trusting it. RFC 9116 requires it on every security.txt. Remediation: add an Expires field with an ISO 8601 / RFC 3339 timestamp no more than a year out.",
	})
	explain.Register(explain.Doc{
		ID: "SECTXT-003", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain, Category: finding.CategoryHygiene,
		Message: "security.txt's Expires field does not parse as ISO 8601 / RFC 3339.", SpecRef: "RFC 9116 §2.5.5",
		Explanation: "RFC 9116 requires Expires to be a valid ISO 8601 / RFC 3339 date-time (e.g. 2026-12-31T23:59:59Z). A malformed value means compliant clients can't determine whether the file is still valid. Remediation: reformat Expires as a valid RFC 3339 timestamp with an uppercase Z or explicit offset.",
	})
	explain.Register(explain.Doc{
		ID: "SECTXT-004", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain, Category: finding.CategoryDisclosure,
		Message: "security.txt's Expires date is in the past.", SpecRef: "RFC 9116 §2.5.5",
		Explanation: "Per RFC 9116 §2.5.5, once Expires has passed the file must be treated as stale by compliant clients, so the domain effectively has no valid disclosure channel even though a file exists at the URL. Remediation: refresh Expires immediately; consider automating renewal (see --fix).",
	})
	explain.Register(explain.Doc{
		ID: "SECTXT-005", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain, Category: finding.CategoryHygiene,
		Message: "security.txt's Expires date is more than one year out, exceeding RFC 9116's recommended maximum validity window.", SpecRef: "RFC 9116 §2.5.5",
		Explanation: "RFC 9116 recommends Expires not exceed roughly one year out, since a long-lived file is more likely to go stale (wrong contact, dead key) without anyone noticing. Remediation: shorten Expires to within a year and set a recurring reminder to renew it.",
	})
	explain.Register(explain.Doc{
		ID: "SECTXT-006", Severity: finding.SeverityInfo, Confidence: finding.ConfidenceCertain, Category: finding.CategoryDisclosure,
		Message: "security.txt's Expires date is valid.", SpecRef: "RFC 9116 §2.5.5",
		Explanation: "Informational: Expires parses correctly and falls within a sane window. No action needed.",
	})
	explain.Register(explain.Doc{
		ID: "SECTXT-007", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain, Category: finding.CategoryHygiene,
		Message: "security.txt's Canonical field does not match the URL it was actually fetched from.", SpecRef: "RFC 9116 §2.5.4",
		Explanation: "Canonical tells clients which URL(s) are the authoritative location(s) of this file, which matters when it's mirrored or fetched via a CDN. A Canonical value that doesn't include the URL actually serving the file suggests stale configuration or a copy-paste from another domain's template. Remediation: update Canonical to list the real URL(s) this file is served from.",
	})
	explain.Register(explain.Doc{
		ID: "SECTXT-008", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain, Category: finding.CategoryHygiene,
		Message: "security.txt was served from /security.txt instead of the canonical /.well-known/security.txt location.", SpecRef: "RFC 9116 §3",
		Explanation: "RFC 9116 designates /.well-known/security.txt as canonical; a legacy top-level /security.txt is only meant as an optional courtesy redirect toward it, not the primary location. Serving the well-known path itself from the legacy location is backwards. Remediation: serve the real file at /.well-known/security.txt, optionally redirecting /security.txt to it.",
	})
	explain.Register(explain.Doc{
		ID: "SECTXT-009", Severity: finding.SeverityInfo, Confidence: finding.ConfidenceCertain, Category: finding.CategoryDisclosure,
		Message: "security.txt carries a PGP signature.", SpecRef: "RFC 9116 §2.5",
		Explanation: "Informational: the file is clearsigned or carries a detached PGP signature, which lets researchers verify it hasn't been tampered with in transit. No action needed unless SECTXT-010 also fired.",
	})
	explain.Register(explain.Doc{
		ID: "SECTXT-010", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceLikely, Category: finding.CategoryDisclosure,
		Message: "security.txt is signed but the PGP key referenced by Encryption could not be verified.", SpecRef: "RFC 9116 §2.5.2",
		Explanation: "A signed file with an unreachable or invalid Encryption key can't actually be verified by anyone following the published instructions, which defeats the purpose of signing it in the first place. magpie's check is structural (the key must be fetchable and look like a PGP public key block), not a full cryptographic verification. Remediation: fix the Encryption URL so it serves a valid PGP public key.",
	})
	explain.Register(explain.Doc{
		ID: "SECTXT-011", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain, Category: finding.CategoryHygiene,
		Message: "security.txt contains a field not defined by RFC 9116 or a registered extension.", SpecRef: "RFC 9116 §2.5.9",
		Explanation: "Unknown fields are usually harmless (a typo, or a private extension a client won't understand) but are worth a second look in case they indicate a misconfigured field name that was meant to be a standard one. Remediation: correct the field name if it was a typo, or ignore it if it's an intentional private extension.",
	})
	explain.Register(explain.Doc{
		ID: "SECTXT-012", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain, Category: finding.CategoryHygiene,
		Message: "A line in security.txt does not follow the required \"Field-Name: value\" syntax.", SpecRef: "RFC 9116 §2.5",
		Explanation: "security.txt uses a simple line-based Field-Name: value syntax; anything else (besides comments starting with # and blank lines) is a parse error for compliant clients. Remediation: fix the malformed line to either match the field syntax or be a # comment.",
	})
}

// SecurityTxtValidator validates /.well-known/security.txt against RFC 9116.
type SecurityTxtValidator struct{}

func (SecurityTxtValidator) Path() string { return "security.txt" }

// knownSecurityTxtFields are the fields defined by RFC 9116 §2.5 plus the
// CSAF extension registered in the IANA "security.txt fields" registry.
var knownSecurityTxtFields = map[string]bool{
	"Contact":             true,
	"Expires":             true,
	"Encryption":          true,
	"Acknowledgments":     true,
	"Canonical":           true,
	"Policy":              true,
	"Hiring":              true,
	"Preferred-Languages": true,
	"CSAF":                true,
}

var fieldLineRe = regexp.MustCompile(`^([A-Za-z][A-Za-z-]*)\s*:\s*(.*)$`)

type sectxtLine struct {
	LineNo    int
	Raw       string
	Name      string // canonical field name, "" if not a field line
	Value     string
	Malformed bool
	Comment   bool
	Blank     bool
}

type parsedSecurityTxt struct {
	Lines               []sectxtLine
	Fields              map[string][]string // canonical name -> values in file order
	HasSignature        bool
	SignatureType       string // "clearsign", "detached", ""
	FieldAfterSignature bool
}

func canonicalFieldName(name string) (string, bool) {
	for known := range knownSecurityTxtFields {
		if strings.EqualFold(known, name) {
			return known, true
		}
	}
	// Preserve the author's casing for unknown fields so the finding
	// evidence is legible, but normalize to Title-Hyphen-Case for display.
	return name, false
}

func parseSecurityTxt(body []byte) parsedSecurityTxt {
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	rawLines := strings.Split(text, "\n")

	p := parsedSecurityTxt{Fields: map[string][]string{}}

	inClearsignHeader := false
	inSignatureBlock := false
	pastSignature := false

	for i, raw := range rawLines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(raw)

		switch {
		case trimmed == "-----BEGIN PGP SIGNED MESSAGE-----":
			p.HasSignature = true
			p.SignatureType = "clearsign"
			inClearsignHeader = true
			p.Lines = append(p.Lines, sectxtLine{LineNo: lineNo, Raw: raw, Comment: true})
			continue
		case inClearsignHeader:
			// Clearsign armor emits "Hash: ..." header lines followed by a
			// blank line before the actual content resumes.
			if trimmed == "" {
				inClearsignHeader = false
			}
			p.Lines = append(p.Lines, sectxtLine{LineNo: lineNo, Raw: raw, Comment: true})
			continue
		case trimmed == "-----BEGIN PGP SIGNATURE-----":
			if !p.HasSignature {
				p.HasSignature = true
				p.SignatureType = "detached"
			}
			inSignatureBlock = true
			p.Lines = append(p.Lines, sectxtLine{LineNo: lineNo, Raw: raw, Comment: true})
			continue
		case trimmed == "-----END PGP SIGNATURE-----":
			inSignatureBlock = false
			pastSignature = true
			p.Lines = append(p.Lines, sectxtLine{LineNo: lineNo, Raw: raw, Comment: true})
			continue
		case inSignatureBlock:
			p.Lines = append(p.Lines, sectxtLine{LineNo: lineNo, Raw: raw, Comment: true})
			continue
		}

		if trimmed == "" {
			p.Lines = append(p.Lines, sectxtLine{LineNo: lineNo, Raw: raw, Blank: true})
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			p.Lines = append(p.Lines, sectxtLine{LineNo: lineNo, Raw: raw, Comment: true})
			continue
		}

		m := fieldLineRe.FindStringSubmatch(trimmed)
		if m == nil || strings.TrimSpace(m[2]) == "" {
			p.Lines = append(p.Lines, sectxtLine{LineNo: lineNo, Raw: raw, Malformed: true})
			continue
		}

		canonical, _ := canonicalFieldName(m[1])
		value := strings.TrimSpace(m[2])
		p.Lines = append(p.Lines, sectxtLine{LineNo: lineNo, Raw: raw, Name: canonical, Value: value})
		p.Fields[canonical] = append(p.Fields[canonical], value)
		if pastSignature {
			p.FieldAfterSignature = true
		}
	}

	return p
}

const maxExpiresValidity = 365 * 24 * time.Hour

func (SecurityTxtValidator) Validate(ctx Context) Output {
	out := Output{Facts: Facts{}}
	r := ctx.Result

	if r.Presence != scan.PresencePresent {
		return out
	}

	p := parseSecurityTxt(r.Body)
	out.Facts["has_signature"] = strconv.FormatBool(p.HasSignature)
	out.Facts["signature_type"] = p.SignatureType

	// --- Required fields -------------------------------------------------
	if len(p.Fields["Contact"]) == 0 {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "SECTXT-001", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryDisclosure,
			Message:  "security.txt is missing the required Contact field.",
			Evidence: finalURL(r), SpecRef: "RFC 9116 §2.5.3",
		})
	} else {
		out.Facts["contact_count"] = strconv.Itoa(len(p.Fields["Contact"]))
		out.Facts["contact_values"] = strings.Join(p.Fields["Contact"], "|")
		analyzeContacts(p.Fields["Contact"], ctx.Host, &out)
	}

	if len(p.Fields["Expires"]) == 0 {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "SECTXT-002", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryDisclosure,
			Message:  "security.txt is missing the required Expires field.",
			Evidence: finalURL(r), SpecRef: "RFC 9116 §2.5.5",
		})
	} else {
		validateExpires(p.Fields["Expires"][0], &out)
	}

	// --- Canonical ---------------------------------------------------------
	if canon := p.Fields["Canonical"]; len(canon) > 0 {
		out.Facts["canonical_values"] = strings.Join(canon, "|")
		if !anyCanonicalMatches(canon, finalURL(r)) {
			out.Findings = append(out.Findings, finding.Finding{
				ID: "SECTXT-007", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain,
				Category: finding.CategoryHygiene,
				Message:  "security.txt's Canonical field does not match the URL it was actually fetched from.",
				Evidence: strings.Join(canon, ", ") + " vs " + finalURL(r), SpecRef: "RFC 9116 §2.5.4",
			})
		}
	}

	// --- Served from legacy /security.txt ---------------------------------
	if servedPath := urlPath(finalURL(r)); servedPath == "/security.txt" {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "SECTXT-008", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryHygiene,
			Message:  "security.txt was served from /security.txt instead of the canonical /.well-known/security.txt location.",
			Evidence: finalURL(r), SpecRef: "RFC 9116 §3",
		})
	}

	// --- PGP signature -------------------------------------------------
	if p.HasSignature {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "SECTXT-009", Severity: finding.SeverityInfo, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryDisclosure,
			Message:  "security.txt carries a " + p.SignatureType + " PGP signature.",
			Evidence: finalURL(r), SpecRef: "RFC 9116 §2.5",
		})
		validateSignature(p, ctx, &out)
	}

	// --- Unknown / malformed fields ----------------------------------------
	reportFieldIssues(p, r, &out)

	out.Facts["policy_present"] = strconv.FormatBool(len(p.Fields["Policy"]) > 0)
	out.Facts["preferred_languages_present"] = strconv.FormatBool(len(p.Fields["Preferred-Languages"]) > 0)
	out.Facts["acknowledgments_present"] = strconv.FormatBool(len(p.Fields["Acknowledgments"]) > 0)
	out.Facts["hiring_present"] = strconv.FormatBool(len(p.Fields["Hiring"]) > 0)
	out.Facts["expires_duplicate"] = strconv.FormatBool(len(p.Fields["Expires"]) > 1)
	out.Facts["field_after_signature"] = strconv.FormatBool(p.FieldAfterSignature)
	out.Facts["mentions_mobile_scope"] = strconv.FormatBool(anyFieldValueContains(p, "mobile"))
	if enc := p.Fields["Encryption"]; len(enc) > 0 {
		out.Facts["encryption_url"] = enc[0]
	}

	return out
}

// anyFieldValueContains reports whether any field value in p contains
// substr, case-insensitively.
func anyFieldValueContains(p parsedSecurityTxt, substr string) bool {
	substr = strings.ToLower(substr)
	for _, values := range p.Fields {
		for _, v := range values {
			if strings.Contains(strings.ToLower(v), substr) {
				return true
			}
		}
	}
	return false
}

// analyzeContacts derives contact_form_only (true when every Contact value
// is an http(s) form URL with no mailto: or tel: alternative) and
// contact_external_domain (the first contact URL whose registrable domain
// differs from the target host's, empty if none).
func analyzeContacts(contacts []string, host string, out *Output) {
	if len(contacts) == 0 {
		return
	}
	allHTTP := true
	externalDomain := ""
	targetDomain := domainutil.Registrable(host)

	for _, c := range contacts {
		switch {
		case strings.HasPrefix(strings.ToLower(c), "mailto:"), strings.HasPrefix(strings.ToLower(c), "tel:"):
			allHTTP = false
		case strings.HasPrefix(strings.ToLower(c), "http://"), strings.HasPrefix(strings.ToLower(c), "https://"):
			if u, err := url.Parse(c); err == nil && u.Hostname() != "" {
				if externalDomain == "" && !domainutil.SameRegistrable(u.Hostname(), targetDomain) {
					externalDomain = u.Hostname()
				}
			}
		default:
			allHTTP = false
		}
	}

	out.Facts["contact_form_only"] = strconv.FormatBool(allHTTP)
	out.Facts["contact_external_domain"] = externalDomain
}

func validateExpires(raw string, out *Output) {
	out.Facts["expires_raw"] = raw
	expires, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "SECTXT-003", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryHygiene,
			Message:  "security.txt's Expires field does not parse as ISO 8601 / RFC 3339.",
			Evidence: raw, SpecRef: "RFC 9116 §2.5.5",
		})
		return
	}
	out.Facts["expires"] = expires.UTC().Format(time.RFC3339)

	now := time.Now()
	daysRemaining := int(expires.Sub(now).Hours() / 24)
	out.Facts["expires_days_remaining"] = strconv.Itoa(daysRemaining)

	switch {
	case expires.Before(now):
		out.Findings = append(out.Findings, finding.Finding{
			ID: "SECTXT-004", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryDisclosure,
			Message:  "security.txt's Expires date is in the past.",
			Evidence: "expired " + strconv.Itoa(-daysRemaining) + " day(s) ago (" + raw + ")",
			SpecRef:  "RFC 9116 §2.5.5",
		})
	case expires.After(now.Add(maxExpiresValidity)):
		out.Findings = append(out.Findings, finding.Finding{
			ID: "SECTXT-005", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryHygiene,
			Message:  "security.txt's Expires date is more than one year out, exceeding RFC 9116's recommended maximum validity window.",
			Evidence: strconv.Itoa(daysRemaining) + " day(s) remaining (" + raw + ")",
			SpecRef:  "RFC 9116 §2.5.5",
		})
	default:
		out.Findings = append(out.Findings, finding.Finding{
			ID: "SECTXT-006", Severity: finding.SeverityInfo, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryDisclosure,
			Message:  "security.txt's Expires date is valid.",
			Evidence: strconv.Itoa(daysRemaining) + " day(s) remaining (" + raw + ")",
			SpecRef:  "RFC 9116 §2.5.5",
		})
	}
}

// pgpKeyBlockMarker is what a fetched Encryption key must structurally
// contain for magpie's best-effort, dependency-free key check to pass.
// magpie performs no cryptographic signature verification: it confirms the
// referenced key is reachable and looks like a PGP public key block, which
// is the extent of what a passive, read-only tool can safely assert without
// pulling in a full OpenPGP implementation.
const pgpKeyBlockMarker = "-----BEGIN PGP PUBLIC KEY BLOCK-----"

func validateSignature(p parsedSecurityTxt, ctx Context, out *Output) {
	enc := p.Fields["Encryption"]
	if len(enc) == 0 {
		return
	}
	target := enc[0]
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		// Not a fetchable URL (e.g. openpgp4fpr: fingerprint) — nothing to
		// verify passively.
		return
	}
	if ctx.Fetch == nil {
		return
	}

	out.Facts["encryption_scheme"] = "url"
	keyResult, err := ctx.Fetch(target)
	if err != nil || keyResult.Presence != scan.PresencePresent {
		out.Facts["encryption_key_reachable"] = "false"
		out.Findings = append(out.Findings, finding.Finding{
			ID: "SECTXT-010", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceLikely,
			Category: finding.CategoryDisclosure,
			Message:  "security.txt is signed but the PGP key referenced by Encryption could not be verified.",
			Evidence: target, SpecRef: "RFC 9116 §2.5.2",
		})
		return
	}
	out.Facts["encryption_key_reachable"] = "true"

	if !strings.Contains(string(keyResult.Body), pgpKeyBlockMarker) {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "SECTXT-010", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceLikely,
			Category: finding.CategoryDisclosure,
			Message:  "security.txt is signed but the PGP key referenced by Encryption could not be verified.",
			Evidence: target + " does not contain a PGP public key block", SpecRef: "RFC 9116 §2.5.2",
		})
	}
}

func reportFieldIssues(p parsedSecurityTxt, r scan.Result, out *Output) {
	seenUnknown := map[string]bool{}
	for _, line := range p.Lines {
		switch {
		case line.Malformed:
			out.Findings = append(out.Findings, finding.Finding{
				ID: "SECTXT-012", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain,
				Category: finding.CategoryHygiene,
				Message:  "A line in security.txt does not follow the required \"Field-Name: value\" syntax.",
				Evidence: "line " + strconv.Itoa(line.LineNo) + ": " + strings.TrimSpace(line.Raw),
				SpecRef:  "RFC 9116 §2.5",
			})
		case line.Name != "" && !knownSecurityTxtFields[line.Name] && !seenUnknown[line.Name]:
			seenUnknown[line.Name] = true
			out.Findings = append(out.Findings, finding.Finding{
				ID: "SECTXT-011", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain,
				Category: finding.CategoryHygiene,
				Message:  "security.txt contains a field not defined by RFC 9116 or a registered extension.",
				Evidence: line.Name, SpecRef: "RFC 9116 §2.5.9",
			})
		}
	}
}

func anyCanonicalMatches(canonical []string, fetched string) bool {
	fu, err := url.Parse(fetched)
	if err != nil {
		return false
	}
	for _, c := range canonical {
		cu, err := url.Parse(c)
		if err != nil {
			continue
		}
		if strings.EqualFold(cu.Scheme, fu.Scheme) &&
			strings.EqualFold(cu.Host, fu.Host) &&
			strings.TrimRight(cu.Path, "/") == strings.TrimRight(fu.Path, "/") {
			return true
		}
	}
	return false
}

func urlPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Path
}
