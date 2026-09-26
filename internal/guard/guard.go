package guard

import (
	"context"
	"errors"
	"time"

	"github.com/Loccao102/Agent-Guard/internal/approval"
	"github.com/Loccao102/Agent-Guard/internal/audit"
	"github.com/Loccao102/Agent-Guard/internal/policy"
	"github.com/Loccao102/Agent-Guard/internal/risk"
)

type Action struct {
	Agent string            `json:"agent"`
	Kind  string            `json:"kind"`
	Value string            `json:"value"`
	Meta  map[string]string `json:"meta,omitempty"`
	Args  map[string]any    `json:"args,omitempty"`
}

type Result struct {
	Decision    string   `json:"decision"`
	Risk        string   `json:"risk"`
	Reason      string   `json:"reason"`
	RuleID      string   `json:"rule_id,omitempty"`
	RiskReasons []string `json:"risk_reasons,omitempty"`
	ApprovalID  string   `json:"approval_id,omitempty"`
	Pending     bool     `json:"pending,omitempty"`
	Remembered  bool     `json:"remembered,omitempty"`
}

type Guard struct {
	engine   *policy.Engine
	analyzer risk.Analyzer
	store    *audit.Store
	broker   *approval.Broker
}

func New(engine *policy.Engine, analyzer risk.Analyzer, store *audit.Store, broker *approval.Broker) *Guard {
	return &Guard{engine: engine, analyzer: analyzer, store: store, broker: broker}
}
func (g *Guard) Broker() *approval.Broker { return g.broker }

func (g *Guard) Evaluate(ctx context.Context, action Action, wait bool) (Result, error) {
	if g.broker.HasGrant(action.Agent, action.Kind, action.Value) {
		r := g.analyzer.Analyze(action.Kind, action.Value)
		result := Result{Decision: policy.Allow, Risk: r.Level, Reason: "allowed by session approval", RiskReasons: r.Reasons, Remembered: true}
		return result, g.record(action, result)
	}
	decision := g.engine.EvaluateWithArgs(action.Kind, action.Value, action.Args)
	riskResult := g.analyzer.Analyze(action.Kind, action.Value)
	result := Result{Decision: decision.Decision, Risk: riskResult.Level, Reason: decision.Reason, RuleID: decision.RuleID, RiskReasons: riskResult.Reasons}
	if decision.Decision != policy.Ask {
		return result, g.record(action, result)
	}
	req, err := g.broker.Create(action.Agent, action.Kind, action.Value, riskResult.Level, decision.Reason, decision.RuleID)
	if err != nil {
		return Result{}, err
	}
	result.ApprovalID = req.ID
	result.Pending = true
	if !wait {
		return result, g.record(action, result)
	}
	resolution, err := g.broker.Wait(ctx, req.ID)
	if err != nil {
		result.Pending = false
		result.Decision = policy.Deny
		if errors.Is(err, approval.ErrExpired) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			result.Reason = "approval was not completed in time"
		} else {
			result.Reason = "approval could not be completed"
		}
		return result, g.record(action, result)
	}
	result.Pending = false
	result.Decision = resolution.Decision
	result.Remembered = resolution.Remember
	if resolution.Decision == policy.Allow {
		result.Reason = "approved by user"
	} else {
		result.Reason = "denied by user"
	}
	return result, g.record(action, result)
}

// EvaluateBatch performs high-throughput policy and risk evaluation for multiple actions,
// and persists non-blocking audit events using Store.RecordBatch in a single transaction.
func (g *Guard) EvaluateBatch(ctx context.Context, actions []Action) ([]Result, error) {
	if len(actions) == 0 {
		return nil, nil
	}
	results := make([]Result, len(actions))
	auditEvents := make([]audit.Event, 0, len(actions))
	now := time.Now().UTC()

	for i, action := range actions {
		if g.broker.HasGrant(action.Agent, action.Kind, action.Value) {
			r := g.analyzer.Analyze(action.Kind, action.Value)
			results[i] = Result{
				Decision:    policy.Allow,
				Risk:        r.Level,
				Reason:      "allowed by session approval",
				RiskReasons: r.Reasons,
				Remembered:  true,
			}
			auditEvents = append(auditEvents, audit.Event{
				Timestamp: now,
				Agent:     action.Agent,
				Kind:      action.Kind,
				Value:     action.Value,
				Decision:  results[i].Decision,
				Risk:      results[i].Risk,
				Reason:    results[i].Reason,
			})
			continue
		}

		decision := g.engine.EvaluateWithArgs(action.Kind, action.Value, action.Args)
		riskResult := g.analyzer.Analyze(action.Kind, action.Value)
		results[i] = Result{
			Decision:    decision.Decision,
			Risk:        riskResult.Level,
			Reason:      decision.Reason,
			RuleID:      decision.RuleID,
			RiskReasons: riskResult.Reasons,
		}

		if decision.Decision != policy.Ask {
			auditEvents = append(auditEvents, audit.Event{
				Timestamp: now,
				Agent:     action.Agent,
				Kind:      action.Kind,
				Value:     action.Value,
				Decision:  results[i].Decision,
				Risk:      results[i].Risk,
				Reason:    results[i].Reason,
				RuleID:    results[i].RuleID,
			})
			continue
		}

		req, err := g.broker.Create(action.Agent, action.Kind, action.Value, riskResult.Level, decision.Reason, decision.RuleID)
		if err != nil {
			return nil, err
		}
		results[i].ApprovalID = req.ID
		results[i].Pending = true
		auditEvents = append(auditEvents, audit.Event{
			Timestamp: now,
			Agent:     action.Agent,
			Kind:      action.Kind,
			Value:     action.Value,
			Decision:  results[i].Decision,
			Risk:      results[i].Risk,
			Reason:    results[i].Reason,
			RuleID:    results[i].RuleID,
		})
	}

	if len(auditEvents) > 0 {
		if err := g.store.RecordBatch(auditEvents); err != nil {
			return nil, err
		}
	}

	return results, nil
}

func (g *Guard) record(action Action, result Result) error {
	return g.store.Record(audit.Event{Timestamp: time.Now().UTC(), Agent: action.Agent, Kind: action.Kind, Value: action.Value, Decision: result.Decision, Risk: result.Risk, Reason: result.Reason, RuleID: result.RuleID})
}
