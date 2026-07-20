package correlate

import (
	"strconv"
	"strings"
)

type Condition struct {
	Presence      *PresenceCond      `json:"presence,omitempty"`
	Fact          *FactCond          `json:"fact,omitempty"`
	FactCompare   *FactCompareCond   `json:"fact_compare,omitempty"`
	FindingExists *FindingExistsCond `json:"finding_exists,omitempty"`
	CleanCountMin *CleanCountMinCond `json:"clean_count_min,omitempty"`
	And           []Condition        `json:"and,omitempty"`
	Or            []Condition        `json:"or,omitempty"`
	Not           *Condition         `json:"not,omitempty"`
}

type PresenceCond struct {
	Path string   `json:"path"`
	In   []string `json:"in"`
}

type FactCond struct {
	Path  string `json:"path"`
	Key   string `json:"key"`
	Op    string `json:"op"`
	Value string `json:"value,omitempty"`
}

type FactRef struct {
	Path string `json:"path"`
	Key  string `json:"key"`
}

type FactCompareCond struct {
	A  FactRef `json:"a"`
	B  FactRef `json:"b"`
	Op string  `json:"op"`
}

type FindingExistsCond struct {
	Path string `json:"path"`
	ID   string `json:"id"`
}

type CleanCountMinCond struct {
	Min int `json:"min"`
}

func Eval(c *Condition, snap Snapshot) bool {
	if c == nil {
		return false
	}
	switch {
	case c.Presence != nil:
		return evalPresence(c.Presence, snap)
	case c.Fact != nil:
		return evalFact(c.Fact, snap)
	case c.FactCompare != nil:
		return evalFactCompare(c.FactCompare, snap)
	case c.FindingExists != nil:
		return snap.hasFinding(c.FindingExists.Path, c.FindingExists.ID)
	case c.CleanCountMin != nil:
		return snap.cleanCount() >= c.CleanCountMin.Min
	case len(c.And) > 0:
		for i := range c.And {
			if !Eval(&c.And[i], snap) {
				return false
			}
		}
		return true
	case len(c.Or) > 0:
		for i := range c.Or {
			if Eval(&c.Or[i], snap) {
				return true
			}
		}
		return false
	case c.Not != nil:
		return !Eval(c.Not, snap)
	}
	return false
}

func evalPresence(c *PresenceCond, snap Snapshot) bool {
	p := string(snap.presence(c.Path))
	for _, want := range c.In {
		if p == want {
			return true
		}
	}
	return false
}

func evalFact(c *FactCond, snap Snapshot) bool {
	v, ok := snap.fact(c.Path, c.Key)
	switch c.Op {
	case "exists":
		return ok
	case "not_exists":
		return !ok
	}
	if !ok {
		return false
	}
	switch c.Op {
	case "eq":
		return v == c.Value
	case "ne":
		return v != c.Value
	case "contains":
		return strings.Contains(v, c.Value)
	case "not_contains":
		return !strings.Contains(v, c.Value)
	case "not_empty":
		return v != ""
	case "lt", "lte", "gt", "gte":
		fv, err1 := strconv.Atoi(v)
		cv, err2 := strconv.Atoi(c.Value)
		if err1 != nil || err2 != nil {
			return false
		}
		switch c.Op {
		case "lt":
			return fv < cv
		case "lte":
			return fv <= cv
		case "gt":
			return fv > cv
		case "gte":
			return fv >= cv
		}
	}
	return false
}

func evalFactCompare(c *FactCompareCond, snap Snapshot) bool {
	a, aok := snap.fact(c.A.Path, c.A.Key)
	b, bok := snap.fact(c.B.Path, c.B.Key)
	switch c.Op {
	case "eq":
		return aok && bok && a == b
	case "ne":
		return aok && bok && a != b
	case "conflict":
		return aok && bok && a != "" && b != "" && a != b
	}
	return false
}
