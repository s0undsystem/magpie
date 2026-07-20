package render

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/harborproject/magpie/internal/correlate"
	"github.com/harborproject/magpie/internal/explain"
	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/report"
	"github.com/harborproject/magpie/internal/version"
)

func lookupDoc(id string, engine *correlate.Engine) explain.Doc {
	if d, ok := explain.Lookup(id); ok {
		return d
	}
	if r, ok := engine.Rule(id); ok {
		return explain.Doc{
			ID: r.ID, Severity: r.Severity, Confidence: r.Confidence, Category: r.Category,
			Message: r.Message, SpecRef: r.SpecRef, Explanation: r.Explanation,
		}
	}
	return explain.Doc{ID: id}
}

const sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     sarifText           `json:"shortDescription"`
	FullDescription      sarifText           `json:"fullDescription"`
	HelpURI              string              `json:"helpUri,omitempty"`
	Properties           sarifRuleProperties `json:"properties"`
	DefaultConfiguration sarifRuleConfig     `json:"defaultConfiguration"`
}

type sarifRuleProperties struct {
	Category   string `json:"category"`
	Confidence string `json:"confidence"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func SARIF(w io.Writer, rep report.Report, opts Options) error {
	findings := opts.Filter.Apply(rep.Findings)

	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.ID] = true
	}
	ids := make([]string, 0, len(ruleIDs))
	for id := range ruleIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	engine := correlate.NewEngine()
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		doc := lookupDoc(id, engine)
		rules = append(rules, sarifRule{
			ID:                   id,
			Name:                 id,
			ShortDescription:     sarifText{Text: doc.Message},
			FullDescription:      sarifText{Text: doc.Explanation},
			Properties:           sarifRuleProperties{Category: string(doc.Category), Confidence: string(doc.Confidence)},
			DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(doc.Severity)},
		})
	}

	targetURI := "https://" + rep.Domain + "/.well-known/"
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		msg := f.Message
		if f.Evidence != "" {
			msg = msg + " (" + f.Evidence + ")"
		}
		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: targetURI},
				},
			}},
		})
	}

	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "magpie",
				Version:        version.Version,
				InformationURI: "https://github.com/harborproject/magpie",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}
