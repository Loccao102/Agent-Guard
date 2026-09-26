package policy

import (
	"fmt"
	"testing"
	"time"
)

func TestPolicyScale50kTo200k(t *testing.T) {
	rules := []Rule{
		{ID: "deny-secrets", Kind: "file", Match: []string{".env*", "**/.env*", "id_rsa*", "*id_rsa*", "*.pem", "*.key"}, Decision: Deny, Reason: "sensitive secret file"},
		{ID: "allow-docs", Kind: "file", Match: []string{"docs/**", "*.md", "README*"}, Decision: Allow, Reason: "documentation"},
		{ID: "allow-src", Kind: "file", Match: []string{"src/**", "internal/**", "cmd/**"}, Decision: Allow, Reason: "source code"},
		{ID: "deny-destructive-shell", Kind: "shell", Match: []string{"rm -rf*", "*format *", "*mkfs*", "shutdown*"}, Decision: Deny, Reason: "destructive OS command"},
		{ID: "ask-git-push", Kind: "shell", Match: []string{"git push*"}, Decision: Ask, Reason: "remote state change"},
		{ID: "allow-git-status", Kind: "shell", Match: []string{"git status*", "git log*", "git diff*"}, Decision: Allow, Reason: "read-only git inspection"},
		{ID: "allow-mcp-read", Kind: "mcp", Match: []string{"*/list*", "*/search*", "*/get*", "*/read*", "*/fetch*"}, Decision: Allow, Reason: "read-only tool call"},
		{ID: "ask-db-mutation", Kind: "database", Match: []string{"drop *", "delete *", "truncate *"}, Decision: Deny, Reason: "destructive database mutation"},
	}

	engine, err := NewEngine(Ask, rules)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// 1. Stage 1: 50,000 evaluations
	t.Log("Evaluating 50,000 policy actions...")
	start50k := time.Now()
	for i := 0; i < 50000; i++ {
		kind := "file"
		val := "src/components/button.tsx"
		expected := Allow
		switch i % 5 {
		case 0:
			kind = "file"
			val = ".env.production"
			expected = Deny
		case 1:
			kind = "shell"
			val = "git push origin main"
			expected = Ask
		case 2:
			kind = "shell"
			val = "git status"
			expected = Allow
		case 3:
			kind = "mcp"
			val = "database/fetch_user"
			expected = Allow
		case 4:
			kind = "network"
			val = "http://unknown-host.com"
			expected = Ask // default fallback
		}
		res := engine.Evaluate(kind, val)
		if res.Decision != expected {
			t.Fatalf("at eval %d: expected %s, got %s (rule: %s)", i, expected, res.Decision, res.RuleID)
		}
	}
	dur50k := time.Since(start50k)
	t.Logf("Evaluated 50,000 actions in %v (%.0f evals/sec)", dur50k, 50000.0/dur50k.Seconds())

	// 2. Stage 2: 200,000 evaluations
	t.Log("Evaluating 200,000 policy actions...")
	start200k := time.Now()
	for i := 0; i < 200000; i++ {
		kind := "file"
		val := fmt.Sprintf("src/module_%d/index.ts", i%100)
		expected := Allow
		switch i % 8 {
		case 0:
			kind = "file"
			val = fmt.Sprintf("secret/id_rsa_%d", i)
			expected = Deny
		case 1:
			kind = "shell"
			val = "rm -rf /tmp/data"
			expected = Deny
		case 2:
			kind = "shell"
			val = "git diff HEAD~1"
			expected = Allow
		case 3:
			kind = "mcp"
			val = "files/list_all"
			expected = Allow
		case 4:
			kind = "database"
			val = "drop table users"
			expected = Deny
		case 5:
			kind = "shell"
			val = "git push --force origin main"
			expected = Ask
		case 6:
			kind = "file"
			val = "README.md"
			expected = Allow
		case 7:
			kind = "custom"
			val = "unknown action"
			expected = Ask
		}
		res := engine.Evaluate(kind, val)
		if res.Decision != expected {
			t.Fatalf("at eval 200k [%d]: expected %s, got %s (rule: %s)", i, expected, res.Decision, res.RuleID)
		}
	}
	dur200k := time.Since(start200k)
	t.Logf("Evaluated 200,000 actions in %v (%.0f evals/sec)", dur200k, 200000.0/dur200k.Seconds())
}

func BenchmarkPolicyEvaluate50k(b *testing.B) {
	rules := []Rule{
		{ID: "deny-secrets", Kind: "file", Match: []string{".env*", "id_rsa*"}, Decision: Deny, Reason: "secret"},
		{ID: "allow-src", Kind: "file", Match: []string{"src/**", "internal/**"}, Decision: Allow, Reason: "src"},
		{ID: "allow-git", Kind: "shell", Match: []string{"git status*", "git diff*"}, Decision: Allow, Reason: "git"},
	}
	engine, err := NewEngine(Ask, rules)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 50000; j++ {
			_ = engine.Evaluate("file", "src/pkg/main.go")
		}
	}
}
