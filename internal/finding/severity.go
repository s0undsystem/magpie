package finding

import "fmt"

type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

var severityRank = map[Severity]int{
	SeverityInfo:   0,
	SeverityLow:    1,
	SeverityMedium: 2,
	SeverityHigh:   3,
}

func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

func ParseSeverity(s string) (Severity, error) {
	sev := Severity(s)
	if !sev.Valid() {
		return "", fmt.Errorf("invalid severity %q: must be one of info, low, medium, high", s)
	}
	return sev, nil
}
