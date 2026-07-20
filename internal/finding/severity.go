package finding

import "fmt"

// Severity is the impact level of a finding.
type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// severityRank orders severities from least to most severe. Higher is more
// severe.
var severityRank = map[Severity]int{
	SeverityInfo:   0,
	SeverityLow:    1,
	SeverityMedium: 2,
	SeverityHigh:   3,
}

// Rank returns the ordinal rank of the severity, higher meaning more severe.
// Unknown severities rank below SeverityInfo.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

// Valid reports whether s is one of the defined severities.
func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

// ParseSeverity parses a severity from user input (e.g. a CLI flag value).
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(s)
	if !sev.Valid() {
		return "", fmt.Errorf("invalid severity %q: must be one of info, low, medium, high", s)
	}
	return sev, nil
}
