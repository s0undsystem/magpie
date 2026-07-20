package validate

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
)

func init() { Register(MTASTSValidator{}) }

// MTASTSValidator validates /.well-known/mta-sts.txt against RFC 8461.
type MTASTSValidator struct{}

func (MTASTSValidator) Path() string { return "mta-sts.txt" }

const maxMTASTSMaxAge = 31557600 // RFC 8461 §3: max_age MUST NOT be greater than 31557600 (1 year).

var mtaSTSDNSRecordRe = regexp.MustCompile(`^v=STSv1;\s*id=([A-Za-z0-9]+)\s*;?$`)

func (MTASTSValidator) Validate(ctx Context) Output {
	out := Output{Facts: Facts{}}
	r := ctx.Result
	if r.Presence != scan.PresencePresent {
		return out
	}

	fields := map[string][]string{}
	for _, line := range strings.Split(strings.ReplaceAll(string(r.Body), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		fields[key] = append(fields[key], val)
	}

	version := first(fields["version"])
	if version != "STSv1" {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "MTASTS-007", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryMail,
			Message:  "mta-sts.txt is missing or declares an unsupported version; it must be \"STSv1\".",
			Evidence: finalURL(r), SpecRef: "RFC 8461 §3",
		})
	}

	mode := first(fields["mode"])
	out.Facts["mode"] = mode
	switch mode {
	case "enforce":
		// No finding; this is the desired state.
	case "testing":
		out.Findings = append(out.Findings, finding.Finding{
			ID: "MTASTS-001", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryMail,
			Message:  "mta-sts.txt is in testing mode; enforcement is not yet active.",
			Evidence: finalURL(r), SpecRef: "RFC 8461 §5",
		})
	case "none":
		out.Findings = append(out.Findings, finding.Finding{
			ID: "MTASTS-002", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryMail,
			Message:  "mta-sts.txt explicitly disables MTA-STS enforcement (mode: none).",
			Evidence: finalURL(r), SpecRef: "RFC 8461 §5",
		})
	default:
		out.Findings = append(out.Findings, finding.Finding{
			ID: "MTASTS-003", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryMail,
			Message:  "mta-sts.txt is missing a valid mode field; it must be one of enforce, testing, or none.",
			Evidence: finalURL(r), SpecRef: "RFC 8461 §3",
		})
	}

	maxAgeRaw := first(fields["max_age"])
	if maxAge, err := strconv.Atoi(maxAgeRaw); err != nil || maxAge <= 0 || maxAge > maxMTASTSMaxAge {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "MTASTS-004", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryMail,
			Message:  "mta-sts.txt's max_age is missing or outside the valid range (1 to 31557600 seconds).",
			Evidence: maxAgeRaw, SpecRef: "RFC 8461 §3",
		})
	} else {
		out.Facts["max_age"] = maxAgeRaw
	}

	mxEntries := fields["mx"]
	if len(mxEntries) == 0 {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "MTASTS-005", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryMail,
			Message:  "mta-sts.txt does not list any mx patterns; no mail servers are covered by the policy.",
			Evidence: finalURL(r), SpecRef: "RFC 8461 §3",
		})
	} else {
		out.Facts["mx_count"] = strconv.Itoa(len(mxEntries))
		out.Facts["mx_patterns"] = strings.Join(mxEntries, ",")
	}

	if ctx.LookupTXT != nil {
		validateDNSRecord(ctx, &out)
	}

	return out
}

func validateDNSRecord(ctx Context, out *Output) {
	name := "_mta-sts." + ctx.Host
	records, err := ctx.LookupTXT(name)
	if err != nil || len(records) == 0 {
		out.Facts["mta_sts_dns_txt_present"] = "false"
		return
	}
	out.Facts["mta_sts_dns_txt_present"] = "true"

	for _, rec := range records {
		m := mtaSTSDNSRecordRe.FindStringSubmatch(strings.TrimSpace(rec))
		if m != nil {
			out.Facts["mta_sts_dns_txt_id"] = m[1]
			if age, ok := policyIDAgeDays(m[1]); ok {
				out.Facts["mta_sts_dns_txt_id_age_days"] = strconv.Itoa(age)
			}
			return
		}
	}

	out.Findings = append(out.Findings, finding.Finding{
		ID: "MTASTS-006", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceLikely,
		Category: finding.CategoryMail,
		Message:  "The _mta-sts DNS TXT record is malformed; it must read \"v=STSv1; id=<id>\".",
		Evidence: name, SpecRef: "RFC 8461 §3.1",
	})
}

// policyIDAgeDays attempts to interpret a policy id as a timestamp, per the
// common (but not mandatory) RFC 8461 convention of using one, and returns
// its age in days. RFC 8461 does not mandate a format, so ids that don't
// parse as a recognized timestamp return ok=false and the age is treated as
// not inferable.
func policyIDAgeDays(id string) (days int, ok bool) {
	for _, layout := range []string{"20060102150405Z0700", "2006010215Z0700", time.RFC3339} {
		normalized := id
		if !strings.Contains(id, "+") && !strings.HasSuffix(id, "Z") && (layout == "20060102150405Z0700" || layout == "2006010215Z0700") {
			normalized = id + "Z"
		}
		if t, err := time.Parse(layout, normalized); err == nil {
			return int(time.Since(t).Hours() / 24), true
		}
	}
	return 0, false
}

func first(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}
