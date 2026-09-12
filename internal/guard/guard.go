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
	Agent string `json:"agent"`
	Kind string `json:"kind"`
	Value string `json:"value"`
	Meta map[string]string `json:"meta,omitempty"`
}

type Result struct {
	Decision string `json:"decision"`
	Risk string `json:"risk"`
	Reason string `json:"reason"`
	RuleID string `json:"rule_id,omitempty"`
	RiskReasons []string `json:"risk_reasons,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
	Pending bool `json:"pending,omitempty"`
	Remembered bool `json:"remembered,omitempty"`
}

type Guard struct {
	engine *policy.Engine
	analyzer risk.Analyzer
	store *audit.Store
	broker *approval.Broker
}

func New(engine *policy.Engine, analyzer risk.Analyzer, store *audit.Store, broker *approval.Broker) *Guard {
	return &Guard{engine:engine, analyzer:analyzer, store:store, broker:broker}
}
func (g *Guard) Broker() *approval.Broker { return g.broker }

func (g *Guard) Evaluate(ctx context.Context, action Action, wait bool) (Result,error) {
	if g.broker.HasGrant(action.Agent,action.Kind,action.Value) {
		r:=g.analyzer.Analyze(action.Kind,action.Value)
		result:=Result{Decision:policy.Allow,Risk:r.Level,Reason:"allowed by session approval",RiskReasons:r.Reasons,Remembered:true}
		return result,g.record(action,result)
	}
	decision:=g.engine.Evaluate(action.Kind,action.Value)
	riskResult:=g.analyzer.Analyze(action.Kind,action.Value)
	result:=Result{Decision:decision.Decision,Risk:riskResult.Level,Reason:decision.Reason,RuleID:decision.RuleID,RiskReasons:riskResult.Reasons}
	if decision.Decision!=policy.Ask { return result,g.record(action,result) }
	req,err:=g.broker.Create(action.Agent,action.Kind,action.Value,riskResult.Level,decision.Reason,decision.RuleID)
	if err!=nil{return Result{},err}
	result.ApprovalID=req.ID;result.Pending=true
	if !wait{return result,g.record(action,result)}
	resolution,err:=g.broker.Wait(ctx,req.ID)
	if err!=nil {
		result.Pending=false;result.Decision=policy.Deny
		if errors.Is(err,approval.ErrExpired)||errors.Is(err,context.DeadlineExceeded)||errors.Is(err,context.Canceled){result.Reason="approval was not completed in time"}else{result.Reason="approval could not be completed"}
		return result,g.record(action,result)
	}
	result.Pending=false;result.Decision=resolution.Decision;result.Remembered=resolution.Remember
	if resolution.Decision==policy.Allow{result.Reason="approved by user"}else{result.Reason="denied by user"}
	return result,g.record(action,result)
}

func (g *Guard) record(action Action,result Result) error {
	return g.store.Record(audit.Event{Timestamp:time.Now().UTC(),Agent:action.Agent,Kind:action.Kind,Value:action.Value,Decision:result.Decision,Risk:result.Risk,Reason:result.Reason,RuleID:result.RuleID})
}
