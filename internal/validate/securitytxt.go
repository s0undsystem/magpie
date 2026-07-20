package validate

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
)

func init() {
	Register(SecurityTxtValidator{})
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
	Lines         []sectxtLine
	Fields        map[string][]string // canonical name -> values in file order
	HasSignature  bool
	SignatureType string // "clearsign", "detached", ""
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
	if enc := p.Fields["Encryption"]; len(enc) > 0 {
		out.Facts["encryption_url"] = enc[0]
	}

	return out
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
