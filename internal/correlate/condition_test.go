package correlate

import (
	"testing"

	"github.com/harborproject/magpie/internal/finding"
	"github.com/harborproject/magpie/internal/scan"
	"github.com/harborproject/magpie/internal/validate"
)

func snap(docs map[string]DocFacts) Snapshot {
	return Snapshot{Host: "example.org", Docs: docs}
}

func doc(presence scan.Presence, facts map[string]string) DocFacts {
	return DocFacts{Presence: presence, Facts: validate.Facts(facts)}
}

func TestEvalPresence(t *testing.T) {
	s := snap(map[string]DocFacts{"security.txt": doc(scan.PresencePresent, nil)})
	c := &Condition{Presence: &PresenceCond{Path: "security.txt", In: []string{"present"}}}
	if !Eval(c, s) {
		t.Error("expected match")
	}
	c2 := &Condition{Presence: &PresenceCond{Path: "security.txt", In: []string{"absent"}}}
	if Eval(c2, s) {
		t.Error("expected no match")
	}
}

func TestEvalPresenceMissingDoc(t *testing.T) {
	s := snap(map[string]DocFacts{})
	c := &Condition{Presence: &PresenceCond{Path: "security.txt", In: []string{"absent"}}}
	if Eval(c, s) {
		t.Error("a missing doc has empty presence, which should not match \"absent\" literally")
	}
}

func TestEvalFactOps(t *testing.T) {
	s := snap(map[string]DocFacts{"security.txt": doc(scan.PresencePresent, map[string]string{
		"n": "10", "s": "hello world",
	})})

	cases := []struct {
		op, value string
		want      bool
	}{
		{"eq", "10", true}, {"eq", "11", false},
		{"ne", "11", true}, {"ne", "10", false},
		{"contains", "hello", true}, {"contains", "bye", false},
		{"not_contains", "bye", true}, {"not_contains", "hello", false},
		{"not_empty", "", true},
		{"lt", "11", true}, {"lt", "10", false},
		{"lte", "10", true}, {"lte", "9", false},
		{"gt", "9", true}, {"gt", "10", false},
		{"gte", "10", true}, {"gte", "11", false},
	}
	for _, tc := range cases {
		key := "n"
		if tc.op == "contains" || tc.op == "not_contains" || tc.op == "not_empty" {
			key = "s"
		}
		c := &Condition{Fact: &FactCond{Path: "security.txt", Key: key, Op: tc.op, Value: tc.value}}
		if got := Eval(c, s); got != tc.want {
			t.Errorf("op %s value %s: got %v, want %v", tc.op, tc.value, got, tc.want)
		}
	}
}

func TestEvalFactExistsNotExists(t *testing.T) {
	s := snap(map[string]DocFacts{"security.txt": doc(scan.PresencePresent, map[string]string{"n": "10"})})
	if !Eval(&Condition{Fact: &FactCond{Path: "security.txt", Key: "n", Op: "exists"}}, s) {
		t.Error("expected exists=true")
	}
	if Eval(&Condition{Fact: &FactCond{Path: "security.txt", Key: "missing", Op: "exists"}}, s) {
		t.Error("expected exists=false for a missing key")
	}
	if !Eval(&Condition{Fact: &FactCond{Path: "security.txt", Key: "missing", Op: "not_exists"}}, s) {
		t.Error("expected not_exists=true for a missing key")
	}
}

func TestEvalFactMissingFactSafelyFalse(t *testing.T) {
	s := snap(map[string]DocFacts{"security.txt": doc(scan.PresencePresent, nil)})
	c := &Condition{Fact: &FactCond{Path: "security.txt", Key: "nope", Op: "eq", Value: "x"}}
	if Eval(c, s) {
		t.Error("a missing fact should never satisfy a comparison op")
	}
}

func TestEvalFactNonNumericComparison(t *testing.T) {
	s := snap(map[string]DocFacts{"security.txt": doc(scan.PresencePresent, map[string]string{"n": "not-a-number"})})
	c := &Condition{Fact: &FactCond{Path: "security.txt", Key: "n", Op: "lt", Value: "10"}}
	if Eval(c, s) {
		t.Error("a non-numeric fact should not satisfy a numeric comparison")
	}
}

func TestEvalFactCompare(t *testing.T) {
	s := snap(map[string]DocFacts{
		"a": doc(scan.PresencePresent, map[string]string{"issuer": "https://x"}),
		"b": doc(scan.PresencePresent, map[string]string{"issuer": "https://y"}),
	})
	c := &Condition{FactCompare: &FactCompareCond{A: FactRef{"a", "issuer"}, B: FactRef{"b", "issuer"}, Op: "conflict"}}
	if !Eval(c, s) {
		t.Error("expected conflict when values differ")
	}
	c2 := &Condition{FactCompare: &FactCompareCond{A: FactRef{"a", "issuer"}, B: FactRef{"a", "issuer"}, Op: "conflict"}}

	if Eval(c2, s) {
		t.Error("did not expect conflict when comparing identical values")
	}
}

func TestEvalFactCompareMissingSideNoConflict(t *testing.T) {
	s := snap(map[string]DocFacts{"a": doc(scan.PresencePresent, map[string]string{"issuer": "https://x"})})
	c := &Condition{FactCompare: &FactCompareCond{A: FactRef{"a", "issuer"}, B: FactRef{"b", "issuer"}, Op: "conflict"}}
	if Eval(c, s) {
		t.Error("a conflict requires both sides to be present")
	}
}

func TestEvalFindingExists(t *testing.T) {
	d := doc(scan.PresencePresent, nil)
	d.Findings = []finding.Finding{{ID: "SECTXT-010"}}
	s := snap(map[string]DocFacts{"security.txt": d})
	if !Eval(&Condition{FindingExists: &FindingExistsCond{Path: "security.txt", ID: "SECTXT-010"}}, s) {
		t.Error("expected finding_exists to match")
	}
	if Eval(&Condition{FindingExists: &FindingExistsCond{Path: "security.txt", ID: "SECTXT-999"}}, s) {
		t.Error("did not expect a match for an absent finding ID")
	}
}

func TestEvalCleanCountMin(t *testing.T) {
	s := snap(map[string]DocFacts{
		"a": doc(scan.PresencePresent, nil),
		"b": doc(scan.PresencePresent, nil),
		"c": {Presence: scan.PresencePresent, Findings: []finding.Finding{{ID: "X"}}},
		"d": doc(scan.PresenceAbsent, nil),
	})
	if Eval(&Condition{CleanCountMin: &CleanCountMinCond{Min: 3}}, s) {
		t.Error("only 2 docs are clean; min 3 should not match")
	}
	if !Eval(&Condition{CleanCountMin: &CleanCountMinCond{Min: 2}}, s) {
		t.Error("2 clean docs should satisfy min 2")
	}
}

func TestEvalAndOrNot(t *testing.T) {
	s := snap(map[string]DocFacts{"a": doc(scan.PresencePresent, nil)})
	truthy := &Condition{Presence: &PresenceCond{Path: "a", In: []string{"present"}}}
	falsy := &Condition{Presence: &PresenceCond{Path: "a", In: []string{"absent"}}}

	if !Eval(&Condition{And: []Condition{*truthy, *truthy}}, s) {
		t.Error("and(true,true) should be true")
	}
	if Eval(&Condition{And: []Condition{*truthy, *falsy}}, s) {
		t.Error("and(true,false) should be false")
	}
	if !Eval(&Condition{Or: []Condition{*falsy, *truthy}}, s) {
		t.Error("or(false,true) should be true")
	}
	if !Eval(&Condition{Not: falsy}, s) {
		t.Error("not(false) should be true")
	}
}

func TestEvalNilCondition(t *testing.T) {
	if Eval(nil, snap(nil)) {
		t.Error("a nil condition should never match")
	}
}

func TestRenderTemplate(t *testing.T) {
	s := snap(map[string]DocFacts{"security.txt": doc(scan.PresencePresent, map[string]string{"expires_days_remaining": "5"})})
	got := renderTemplate("{{fact:security.txt.expires_days_remaining}} day(s) left on {{host}}", s)
	if got != "5 day(s) left on example.org" {
		t.Errorf("renderTemplate() = %q", got)
	}
}

func TestRenderTemplatePresenceToken(t *testing.T) {
	s := snap(map[string]DocFacts{"security.txt": doc(scan.PresenceAbsent, nil)})
	got := renderTemplate("presence: {{presence:security.txt}}", s)
	if got != "presence: absent" {
		t.Errorf("renderTemplate() = %q", got)
	}
}

func TestRenderTemplateUnknownTokenLeftVerbatim(t *testing.T) {
	s := snap(nil)
	got := renderTemplate("{{nonsense}}", s)
	if got != "{{nonsense}}" {
		t.Errorf("renderTemplate() = %q, want token left as-is", got)
	}
}
