package validate

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/harborproject/magpie/internal/explain"
	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
)

func init() {
	Register(AssetLinksValidator{})

	explain.Register(explain.Doc{
		ID: "AAL-001", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain, Category: finding.CategoryMobile,
		Message: "assetlinks.json is not a valid JSON array of Digital Asset Links statements.", SpecRef: "Android Statements API",
		Explanation: "Android's Digital Asset Links verification expects a top-level JSON array; anything else and Android will silently fail to establish the app-to-website link (breaking App Links / Smart Lock). Remediation: fix whatever generates this file so it emits a JSON array of statement objects.",
	})
	explain.Register(explain.Doc{
		ID: "AAL-002", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain, Category: finding.CategoryMobile,
		Message: "An assetlinks.json statement is missing relation or target.package_name.", SpecRef: "Android Statements API",
		Explanation: "Each statement needs both relation and target.package_name to mean anything to Android's verifier; a statement missing either is inert. Remediation: ensure every statement object has a non-empty relation array and target.package_name.",
	})
	explain.Register(explain.Doc{
		ID: "AAL-003", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain, Category: finding.CategoryMobile,
		Message: "An assetlinks.json relation string does not match the expected \"namespace/permission\" format.", SpecRef: "Android Statements API",
		Explanation: "Relation strings follow a namespace/permission convention (e.g. delegate_permission/common.handle_all_urls); a value that doesn't match this shape is likely a typo that will cause Android to ignore the statement. Remediation: use one of the documented relation strings.",
	})
	explain.Register(explain.Doc{
		ID: "AAL-004", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain, Category: finding.CategoryMobile,
		Message: "An assetlinks.json sha256_cert_fingerprints entry is not a valid colon-separated SHA-256 fingerprint.", SpecRef: "Android Statements API",
		Explanation: "A malformed fingerprint means Android can never match the app's actual signing certificate against this statement, so the link will simply never verify. Remediation: regenerate the fingerprint as 32 uppercase colon-separated hex byte pairs, e.g. via `keytool -list -v`.",
	})
}

type AssetLinksValidator struct{}

func (AssetLinksValidator) Path() string { return "assetlinks.json" }

type assetLinkTarget struct {
	Namespace              string   `json:"namespace"`
	PackageName            string   `json:"package_name"`
	SHA256CertFingerprints []string `json:"sha256_cert_fingerprints"`
}

type assetLinkStatement struct {
	Relation []string        `json:"relation"`
	Target   assetLinkTarget `json:"target"`
}

var relationRe = regexp.MustCompile(`^[a-z0-9_]+(/[a-z0-9_.]+)+$`)
var sha256FingerprintRe = regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`)

func (AssetLinksValidator) Validate(ctx Context) Output {
	out := Output{Facts: Facts{}}
	r := ctx.Result
	if r.Presence != scan.PresencePresent {
		return out
	}

	var statements []assetLinkStatement
	if err := json.Unmarshal(r.Body, &statements); err != nil {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "AAL-001", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryMobile,
			Message:  "assetlinks.json is not a valid JSON array of Digital Asset Links statements.",
			Evidence: finalURL(r), SpecRef: "Android Statements API",
		})
		return out
	}

	var packages []string
	var relations []string
	for _, s := range statements {
		if len(s.Relation) == 0 || s.Target.PackageName == "" {
			out.Findings = append(out.Findings, finding.Finding{
				ID: "AAL-002", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain,
				Category: finding.CategoryMobile,
				Message:  "An assetlinks.json statement is missing relation or target.package_name.",
				Evidence: finalURL(r), SpecRef: "Android Statements API",
			})
		}

		for _, rel := range s.Relation {
			relations = append(relations, rel)
			if !relationRe.MatchString(rel) {
				out.Findings = append(out.Findings, finding.Finding{
					ID: "AAL-003", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain,
					Category: finding.CategoryMobile,
					Message:  "An assetlinks.json relation string does not match the expected \"namespace/permission\" format.",
					Evidence: rel, SpecRef: "Android Statements API",
				})
			}
		}

		if s.Target.PackageName != "" {
			packages = append(packages, s.Target.PackageName)
		}

		for _, fp := range s.Target.SHA256CertFingerprints {
			if !sha256FingerprintRe.MatchString(fp) {
				out.Findings = append(out.Findings, finding.Finding{
					ID: "AAL-004", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain,
					Category: finding.CategoryMobile,
					Message:  "An assetlinks.json sha256_cert_fingerprints entry is not a valid colon-separated SHA-256 fingerprint.",
					Evidence: fp, SpecRef: "Android Statements API",
				})
			}
		}
	}

	if len(packages) > 0 {
		out.Facts["package_names"] = strings.Join(dedupe(packages), ",")
	}
	if len(relations) > 0 {
		out.Facts["relations"] = strings.Join(dedupe(relations), ",")
	}
	out.Facts["statement_count"] = strconv.Itoa(len(statements))

	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
