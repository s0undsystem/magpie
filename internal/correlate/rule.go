package correlate

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/harborproject/magpie/internal/finding"
)

// Rule is one correlation rule: either a declarative condition tree (When)
// or a named builtin evaluator (Builtin) for the handful of rules that
// require real cross-document set logic or DNS lookups the declarative
// condition language can't express (see CONTRIBUTING.md).
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

// BuiltinFunc is a named evaluator for rules that can't be expressed as a
// pure Condition tree. It may return zero, one, or several findings (for
// example CORR-007 emits one finding per offsite redirect found).
type BuiltinFunc func(snap Snapshot, rule Rule, opts EvalOptions) []finding.Finding

// EvalOptions carries optional external capabilities builtin evaluators may
// use. Both are nil-safe; a nil LookupMX simply disables CORR-022.
type EvalOptions struct {
	LookupMX func(host string) ([]string, error)
}

// Engine holds the active rule set (embedded defaults plus any overlay
// loaded via --rules) and the builtin evaluator registry.
type Engine struct {
	rules    []Rule
	builtins map[string]BuiltinFunc
}

// NewEngine returns an Engine seeded with magpie's embedded default rules
// and builtin evaluators.
func NewEngine() *Engine {
	e := &Engine{builtins: map[string]BuiltinFunc{}}
	rules, err := loadEmbeddedRules()
	if err != nil {
		// The embedded ruleset is compiled into the binary; a parse failure
		// here is a build-time bug, not a runtime condition callers can
		// recover from.
		panic("correlate: embedded rules.json is invalid: " + err.Error())
	}
	e.rules = rules
	registerBuiltins(e)
	return e
}

// RegisterBuiltin adds or replaces a named builtin evaluator.
func (e *Engine) RegisterBuiltin(name string, fn BuiltinFunc) {
	e.builtins[name] = fn
}

// LoadOverlay parses additional or overriding rules from JSON and merges
// them into the engine. A rule whose ID matches an existing rule replaces
// it entirely; new IDs are appended. This is what --rules <file> loads.
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

// Rules returns the active rule set sorted by ID, used by the explain
// command.
func (e *Engine) Rules() []Rule {
	rules := append([]Rule(nil), e.rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

// Rule returns the active rule with the given ID, if any.
func (e *Engine) Rule(id string) (Rule, bool) {
	for _, r := range e.rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// Evaluate runs every active rule against snap and returns the findings
// produced, in a fixed ID-sorted rule evaluation order so repeat runs
// against unchanged input are deterministic.
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
