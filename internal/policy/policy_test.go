package policy

import "testing"

func TestEngineFirstMatchWins(t *testing.T) {
	e, err := NewEngine(Ask, []Rule{
		{ID: "secret", Kind: "file", Match: []string{".env*", "**/.env*"}, Decision: Deny, Reason: "secret"},
		{ID: "all-files", Kind: "file", Match: []string{"*"}, Decision: Allow, Reason: "general"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := e.Evaluate("file", ".env.production")
	if got.Decision != Deny || got.RuleID != "secret" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestEngineDefault(t *testing.T) {
	e, err := NewEngine(Ask, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Evaluate("shell", "echo hello"); got.Decision != Ask {
		t.Fatalf("expected ask, got %+v", got)
	}
}

func TestEngineDeepArgsMatching(t *testing.T) {
	e, err := NewEngine(Ask, []Rule{
		{
			ID:       "block-env-writes",
			Kind:     "mcp",
			Match:    []string{"*/write_file*", "*/edit_file*"},
			Args:     map[string][]string{"path": {".env*", "**/.env*", "*.key"}},
			Decision: Deny,
			Reason:   "env writes blocked",
		},
		{
			ID:       "allow-mcp-files",
			Kind:     "mcp",
			Match:    []string{"*/write_file*"},
			Decision: Allow,
			Reason:   "general write allowed",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Tool write_file with path=".env.local" -> Deny
	got := e.EvaluateWithArgs("mcp", "filesystem/write_file", map[string]any{"path": ".env.local"})
	if got.Decision != Deny || got.RuleID != "block-env-writes" {
		t.Fatalf("expected deny, got %+v", got)
	}

	// 2. Tool write_file with path="src/main.go" -> Allow
	got2 := e.EvaluateWithArgs("mcp", "filesystem/write_file", map[string]any{"path": "src/main.go"})
	if got2.Decision != Allow || got2.RuleID != "allow-mcp-files" {
		t.Fatalf("expected allow, got %+v", got2)
	}

	// 3. Auto-parsed JSON from value string: "filesystem/write_file {\"path\": \".env.production\"}" -> Deny
	got3 := e.Evaluate("mcp", "filesystem/write_file {\"path\": \".env.production\"}")
	if got3.Decision != Deny || got3.RuleID != "block-env-writes" {
		t.Fatalf("expected auto-parsed JSON to deny, got %+v", got3)
	}
}
