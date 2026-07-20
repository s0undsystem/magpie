package finding

import "fmt"

// Confidence describes how a finding was derived, not how likely it is to be
// a "real" problem.
//
//   - Certain: parsed directly from valid, unambiguous content.
//   - Likely: presence determination passed soft404 checks but the response
//     was ambiguous, or a field parsed with recoverable errors.
//   - Inferred: produced by the correlation engine or the inference layer
//     rather than read directly.
type Confidence string

const (
	ConfidenceCertain  Confidence = "certain"
	ConfidenceLikely   Confidence = "likely"
	ConfidenceInferred Confidence = "inferred"
)

// confidenceRank orders confidences from least to most certain.
var confidenceRank = map[Confidence]int{
	ConfidenceInferred: 0,
	ConfidenceLikely:   1,
	ConfidenceCertain:  2,
}

// Rank returns the ordinal rank of the confidence, higher meaning more
// certain. Unknown confidences rank below ConfidenceInferred.
func (c Confidence) Rank() int {
	if r, ok := confidenceRank[c]; ok {
		return r
	}
	return -1
}

// Valid reports whether c is one of the defined confidence levels.
func (c Confidence) Valid() bool {
	_, ok := confidenceRank[c]
	return ok
}

// ParseConfidence parses a confidence level from user input (e.g. a CLI flag
// value).
func ParseConfidence(s string) (Confidence, error) {
	c := Confidence(s)
	if !c.Valid() {
		return "", fmt.Errorf("invalid confidence %q: must be one of certain, likely, inferred", s)
	}
	return c, nil
}
