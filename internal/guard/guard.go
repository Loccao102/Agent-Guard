package guard

import "context"

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

var _ = context.Background
