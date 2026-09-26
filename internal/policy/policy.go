package policy

import (
	"encoding/json"
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
	ID       string              `yaml:"id" json:"id"`
	Kind     string              `yaml:"kind" json:"kind"`
	Match    []string            `yaml:"match" json:"match"`
	Args     map[string][]string `yaml:"args,omitempty" json:"args,omitempty"`
	Decision string              `yaml:"decision" json:"decision"`
	Reason   string              `yaml:"reason" json:"reason"`
}

type Result struct {
	Decision string `json:"decision"`
	RuleID   string `json:"rule_id,omitempty"`
	Reason   string `json:"reason"`
}

type matchType int

const (
	matchRegex matchType = iota
	matchAny
	matchExact
	matchPrefix
	matchSuffix
)

type compiledPattern struct {
	kind matchType
	raw  string
	re   *regexp.Regexp
}

func (cp compiledPattern) matches(valLower, valOriginal string) bool {
	switch cp.kind {
	case matchAny:
		return true
	case matchExact:
		return valLower == cp.raw
	case matchPrefix:
		return strings.HasPrefix(valLower, cp.raw)
	case matchSuffix:
		return strings.HasSuffix(valLower, cp.raw)
	case matchRegex:
		return cp.re.MatchString(valOriginal)
	}
	return false
}

type compiledRule struct {
	rule        Rule
	patterns    []compiledPattern
	argPatterns map[string][]compiledPattern
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
		cr := compiledRule{
			rule:        rule,
			argPatterns: make(map[string][]compiledPattern),
		}
		for _, pattern := range rule.Match {
			cp, err := compilePattern(pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			cr.patterns = append(cr.patterns, cp)
		}
		for argKey, patterns := range rule.Args {
			var cps []compiledPattern
			for _, pattern := range patterns {
				cp, err := compilePattern(pattern)
				if err != nil {
					return nil, fmt.Errorf("rule %s arg %s: %w", rule.ID, argKey, err)
				}
				cps = append(cps, cp)
			}
			cr.argPatterns[argKey] = cps
		}
		e.rules = append(e.rules, cr)
	}
	return e, nil
}

func (e *Engine) Evaluate(kind, value string) Result {
	return e.EvaluateWithArgs(kind, value, nil)
}

func (e *Engine) EvaluateWithArgs(kind, value string, args map[string]any) Result {
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = strings.TrimSpace(value)
	valLower := strings.ToLower(value)

	// If args is empty and value contains JSON, attempt to auto-parse arguments
	if len(args) == 0 && strings.Contains(value, "{") {
		start := strings.Index(value, "{")
		end := strings.LastIndex(value, "}")
		if start >= 0 && end > start {
			var parsed map[string]any
			if json.Unmarshal([]byte(value[start:end+1]), &parsed) == nil {
				args = parsed
			}
		}
	}

	for _, cr := range e.rules {
		if cr.rule.Kind != "*" && cr.rule.Kind != kind {
			continue
		}
		matched := false
		for _, cp := range cr.patterns {
			if cp.matches(valLower, value) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		// Check structured arguments if defined
		if len(cr.argPatterns) > 0 {
			if len(args) == 0 {
				continue
			}
			argsSatisfied := true
			for argKey, argPats := range cr.argPatterns {
				rawVal, exists := args[argKey]
				if !exists {
					argsSatisfied = false
					break
				}
				valStr := fmt.Sprint(rawVal)
				valStrLower := strings.ToLower(valStr)
				argMatched := false
				for _, ap := range argPats {
					if ap.matches(valStrLower, valStr) {
						argMatched = true
						break
					}
				}
				if !argMatched {
					argsSatisfied = false
					break
				}
			}
			if !argsSatisfied {
				continue
			}
		}

		return Result{Decision: cr.rule.Decision, RuleID: cr.rule.ID, Reason: cr.rule.Reason}
	}
	return Result{Decision: e.defaultDecision, Reason: "no rule matched; using default decision"}
}

func compilePattern(pattern string) (compiledPattern, error) {
	p := strings.TrimSpace(pattern)
	if p == "*" {
		return compiledPattern{kind: matchAny}, nil
	}
	if !strings.ContainsAny(p, "*?") {
		return compiledPattern{kind: matchExact, raw: strings.ToLower(p)}, nil
	}
	if strings.HasSuffix(p, "*") && !strings.ContainsAny(p[:len(p)-1], "*?") {
		return compiledPattern{kind: matchPrefix, raw: strings.ToLower(p[:len(p)-1])}, nil
	}
	if strings.HasPrefix(p, "*") && !strings.ContainsAny(p[1:], "*?") {
		return compiledPattern{kind: matchSuffix, raw: strings.ToLower(p[1:])}, nil
	}
	re, err := wildcardRegex(p)
	if err != nil {
		return compiledPattern{}, err
	}
	return compiledPattern{kind: matchRegex, re: re}, nil
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
