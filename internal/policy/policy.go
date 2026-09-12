package policy

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	Allow = "allow"
	Ask   = "ask"
	Deny  = "deny"
)

type Rule struct {
	ID       string   `yaml:"id" json:"id"`
	Kind     string   `yaml:"kind" json:"kind"`
	Match    []string `yaml:"match" json:"match"`
	Decision string   `yaml:"decision" json:"decision"`
	Reason   string   `yaml:"reason" json:"reason"`
}

type Result struct {
	Decision string `json:"decision"`
	RuleID   string `json:"rule_id,omitempty"`
	Reason   string `json:"reason"`
}

type compiledRule struct {
	rule     Rule
	patterns []*regexp.Regexp
}

type Engine struct {
	defaultDecision string
	rules           []compiledRule
}

func NewEngine(defaultDecision string, rules []Rule) (*Engine, error) {
	defaultDecision = strings.ToLower(defaultDecision)
	if !validDecision(defaultDecision) {
		return nil, fmt.Errorf("invalid default decision %q", defaultDecision)
	}

	e := &Engine{defaultDecision: defaultDecision}
	for _, rule := range rules {
		rule.Kind = strings.ToLower(strings.TrimSpace(rule.Kind))
		rule.Decision = strings.ToLower(strings.TrimSpace(rule.Decision))
		if rule.ID == "" || rule.Kind == "" || len(rule.Match) == 0 {
			return nil, fmt.Errorf("rule requires id, kind and match patterns")
		}
		if !validDecision(rule.Decision) {
			return nil, fmt.Errorf("rule %s has invalid decision %q", rule.ID, rule.Decision)
		}
		cr := compiledRule{rule: rule}
		for _, pattern := range rule.Match {
			re, err := wildcardRegex(pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			cr.patterns = append(cr.patterns, re)
		}
		e.rules = append(e.rules, cr)
	}
	return e, nil
}

func (e *Engine) Evaluate(kind, value string) Result {
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = strings.TrimSpace(value)
	for _, cr := range e.rules {
		if cr.rule.Kind != "*" && cr.rule.Kind != kind {
			continue
		}
		for _, re := range cr.patterns {
			if re.MatchString(value) {
				return Result{Decision: cr.rule.Decision, RuleID: cr.rule.ID, Reason: cr.rule.Reason}
			}
		}
	}
	return Result{Decision: e.defaultDecision, Reason: "no rule matched; using default decision"}
}

func validDecision(v string) bool {
	return v == Allow || v == Ask || v == Deny
}

func wildcardRegex(pattern string) (*regexp.Regexp, error) {
	pattern = strings.TrimSpace(pattern)
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
