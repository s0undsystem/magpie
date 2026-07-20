package validate

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/harborproject/magpie/internal/explain"
	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
)

func init() {
	Register(AASAValidator{})

	explain.Register(explain.Doc{
		ID: "AASA-001", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain, Category: finding.CategoryMobile,
		Message: "apple-app-site-association is not valid JSON.", SpecRef: "Apple Developer Documentation: apple-app-site-association",
		Explanation: "iOS fetches and parses this file to establish Universal Links, Shared Web Credentials, and App Clips; invalid JSON means none of that works. Remediation: fix whatever generates this file so it emits valid JSON.",
	})
	explain.Register(explain.Doc{
		ID: "AASA-002", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain, Category: finding.CategoryMobile,
		Message: "apple-app-site-association was served with a content type other than application/json.", SpecRef: "Apple Developer Documentation: apple-app-site-association",
		Explanation: "Apple's own documentation recommends serving this file as application/json (historically it also tolerated no extension with no content type restriction, but application/json is the safe modern default). A mismatched content type is usually harmless but is worth cleaning up. Remediation: set Content-Type: application/json for this path.",
	})
	explain.Register(explain.Doc{
		ID: "AASA-003", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain, Category: finding.CategoryMobile,
		Message: "apple-app-site-association does not contain applinks, webcredentials, or appclips sections.", SpecRef: "Apple Developer Documentation: apple-app-site-association",
		Explanation: "A file with none of the three recognized top-level sections doesn't actually configure anything — it's present but functionally empty. Remediation: add an applinks, webcredentials, or appclips section, or remove the file if it isn't needed.",
	})
}

// AASAValidator validates /.well-known/apple-app-site-association.
type AASAValidator struct{}

func (AASAValidator) Path() string { return "apple-app-site-association" }

type aasaAppLink struct {
	AppID  string   `json:"appID"`
	AppIDs []string `json:"appIDs"`
}

type aasaDoc struct {
	Applinks *struct {
		Details []aasaAppLink `json:"details"`
	} `json:"applinks"`
	Webcredentials *struct {
		Apps []string `json:"apps"`
	} `json:"webcredentials"`
	Appclips *struct {
		Apps []string `json:"apps"`
	} `json:"appclips"`
}

func (AASAValidator) Validate(ctx Context) Output {
	out := Output{Facts: Facts{}}
	r := ctx.Result
	if r.Presence != scan.PresencePresent {
		return out
	}

	if ct := baseContentType(r.ContentType); ct != "application/json" {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "AASA-002", Severity: finding.SeverityLow, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryMobile,
			Message:  "apple-app-site-association was served with a content type other than application/json.",
			Evidence: r.ContentType, SpecRef: "Apple Developer Documentation: apple-app-site-association",
		})
	}

	var doc aasaDoc
	if err := json.Unmarshal(r.Body, &doc); err != nil {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "AASA-001", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryMobile,
			Message:  "apple-app-site-association is not valid JSON.",
			Evidence: finalURL(r), SpecRef: "Apple Developer Documentation: apple-app-site-association",
		})
		return out
	}

	var appIDs []string
	if doc.Applinks != nil {
		for _, d := range doc.Applinks.Details {
			if d.AppID != "" {
				appIDs = append(appIDs, d.AppID)
			}
			appIDs = append(appIDs, d.AppIDs...)
		}
	}
	if doc.Webcredentials != nil {
		appIDs = append(appIDs, doc.Webcredentials.Apps...)
	}
	if doc.Appclips != nil {
		appIDs = append(appIDs, doc.Appclips.Apps...)
	}

	if doc.Applinks == nil && doc.Webcredentials == nil && doc.Appclips == nil {
		out.Findings = append(out.Findings, finding.Finding{
			ID: "AASA-003", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain,
			Category: finding.CategoryMobile,
			Message:  "apple-app-site-association does not contain applinks, webcredentials, or appclips sections.",
			Evidence: finalURL(r), SpecRef: "Apple Developer Documentation: apple-app-site-association",
		})
	}

	var teamIDs, bundleIDs []string
	for _, id := range dedupe(appIDs) {
		teamID, bundleID := splitAppID(id)
		if teamID != "" {
			teamIDs = append(teamIDs, teamID)
		}
		if bundleID != "" {
			bundleIDs = append(bundleIDs, bundleID)
		}
	}
	if len(teamIDs) > 0 {
		out.Facts["team_ids"] = strings.Join(dedupe(teamIDs), ",")
	}
	if len(bundleIDs) > 0 {
		out.Facts["bundle_ids"] = strings.Join(dedupe(bundleIDs), ",")
	}
	out.Facts["app_id_count"] = strconv.Itoa(len(appIDs))

	return out
}

// splitAppID splits an Apple app ID of the form "TEAMID.bundle.id" into its
// team ID and bundle ID parts.
func splitAppID(appID string) (teamID, bundleID string) {
	i := strings.IndexByte(appID, '.')
	if i < 0 {
		return "", appID
	}
	return appID[:i], appID[i+1:]
}
