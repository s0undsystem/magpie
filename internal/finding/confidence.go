package finding

import "fmt"

type Confidence string

const (
	ConfidenceCertain  Confidence = "certain"
	ConfidenceLikely   Confidence = "likely"
	ConfidenceInferred Confidence = "inferred"
)

var confidenceRank = map[Confidence]int{
	ConfidenceInferred: 0,
	ConfidenceLikely:   1,
	ConfidenceCertain:  2,
}

func (c Confidence) Rank() int {
	if r, ok := confidenceRank[c]; ok {
		return r
	}
	return -1
}

func (c Confidence) Valid() bool {
	_, ok := confidenceRank[c]
	return ok
}

func ParseConfidence(s string) (Confidence, error) {
	c := Confidence(s)
	if !c.Valid() {
		return "", fmt.Errorf("invalid confidence %q: must be one of certain, likely, inferred", s)
	}
	return c, nil
}
