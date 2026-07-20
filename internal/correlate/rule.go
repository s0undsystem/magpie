package correlate

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/s0undsystem/magpie/internal/finding"
)

type Rule struct {
	ID          string             `json:"id"`
	Severity    finding.Severity   `json:"severity"`
	Confidence  finding.Confidence `json:"confidence"`
	Category    finding.Category   `json:"category"`
	Message     string             `json:"message"`
	Evidence    string             `json:"evidence,omitempty"`
	Explanation string             `json:"explanation"`
	SpecRef     string             `json:"spec_ref,omitempty"`
	When        *Condition         `json:"when,omitempty"`
	Builtin     string             `json:"builtin,omitempty"`
}

type BuiltinFunc func(snap Snapshot, rule Rule, opts EvalOptions) []finding.Finding

type EvalOptions struct {
	LookupMX func(host string) ([]string, error)
}

type Engine struct {
	rules    []Rule
	builtins map[string]BuiltinFunc
}

func NewEngine() *Engine {
	e := &Engine{builtins: map[string]BuiltinFunc{}}
	rules, err := loadEmbeddedRules()
	if err != nil {

		panic("correlate: embedded rules.json is invalid: " + err.Error())
	}
	e.rules = rules
	registerBuiltins(e)
	return e
}

func (e *Engine) RegisterBuiltin(name string, fn BuiltinFunc) {
	e.builtins[name] = fn
}

func (e *Engine) LoadOverlay(data []byte) error {
	var overlay []Rule
	if err := json.Unmarshal(data, &overlay); err != nil {
		return fmt.Errorf("correlate: parsing rules overlay: %w", err)
	}
	for _, r := range overlay {
		if r.ID == "" {
			return fmt.Errorf("correlate: rules overlay contains a rule with no id")
		}
		e.upsert(r)
	}
	return nil
}

func (e *Engine) upsert(r Rule) {
	for i, existing := range e.rules {
		if existing.ID == r.ID {
			e.rules[i] = r
			return
		}
	}
	e.rules = append(e.rules, r)
}

func (e *Engine) Rules() []Rule {
	rules := append([]Rule(nil), e.rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func (e *Engine) Rule(id string) (Rule, bool) {
	for _, r := range e.rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

func (e *Engine) Evaluate(snap Snapshot, opts EvalOptions) []finding.Finding {
	var out []finding.Finding
	for _, rule := range e.Rules() {
		if rule.Builtin != "" {
			fn, ok := e.builtins[rule.Builtin]
			if !ok {
				continue
			}
			out = append(out, fn(snap, rule, opts)...)
			continue
		}
		if rule.When == nil {
			continue
		}
		if Eval(rule.When, snap) {
			out = append(out, finding.Finding{
				ID:         rule.ID,
				Severity:   rule.Severity,
				Confidence: rule.Confidence,
				Category:   rule.Category,
				Message:    rule.Message,
				Evidence:   renderTemplate(rule.Evidence, snap),
				SpecRef:    rule.SpecRef,
			})
		}
	}
	return out
}
