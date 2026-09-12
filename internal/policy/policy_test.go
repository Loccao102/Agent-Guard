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
