package guard

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Loccao102/Agent-Guard/internal/approval"
	"github.com/Loccao102/Agent-Guard/internal/audit"
	"github.com/Loccao102/Agent-Guard/internal/policy"
	"github.com/Loccao102/Agent-Guard/internal/risk"
)

func TestGuardScale50kTo200k(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	rules := RuleTestPack()
	engine, err := policy.NewEngine(policy.Ask, rules)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "guard_scale.db")
	store, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open audit store: %v", err)
	}
	defer store.Close()

	broker := approval.New(2 * time.Minute)
	g := New(engine, risk.NewAnalyzer(), store, broker)
	ctx := context.Background()

	// 1. EvaluateBatch 50,000 actions
	t.Log("Evaluating & auditing 50,000 actions end-to-end through Guard...")
	actions50k := make([]Action, 50000)
	for i := 0; i < 50000; i++ {
		kind := "file"
		val := fmt.Sprintf("src/component_%d.go", i%200)
		if i%7 == 0 {
			kind = "shell"
			val = fmt.Sprintf("git commit -m 'commit #%d'", i)
		} else if i%13 == 0 {
			kind = "database"
			val = "select * from users"
		}
		actions50k[i] = Action{
			Agent: "test-runner",
			Kind:  kind,
			Value: val,
		}
	}

	start50k := time.Now()
	res50k, err := g.EvaluateBatch(ctx, actions50k)
	if err != nil {
		t.Fatalf("EvaluateBatch 50k failed: %v", err)
	}
	dur50k := time.Since(start50k)
	if len(res50k) != 50000 {
		t.Fatalf("expected 50,000 results, got %d", len(res50k))
	}
	t.Logf("Guard processed 50,000 end-to-end actions in %v (%.0f ops/sec)", dur50k, 50000.0/dur50k.Seconds())

	// Verify audit hash chain after 50k
	v50k, err := store.Verify()
	if err != nil {
		t.Fatalf("audit verify 50k failed: %v", err)
	}
	if !v50k.Valid || v50k.Checked != 50000 {
		t.Fatalf("50k audit verification failed: valid=%v checked=%d", v50k.Valid, v50k.Checked)
	}
	t.Log("Audit hash chain 50,000 records VERIFIED.")

	// 2. EvaluateBatch additional 150,000 actions (total 200k)
	t.Log("Evaluating & auditing 150,000 more actions (reaching 200,000 total)...")
	actions150k := make([]Action, 150000)
	for i := 0; i < 150000; i++ {
		actions150k[i] = Action{
			Agent: "test-runner",
			Kind:  "file",
			Value: fmt.Sprintf("internal/pkg_%d/file.go", i%500),
		}
	}

	start150k := time.Now()
	res150k, err := g.EvaluateBatch(ctx, actions150k)
	if err != nil {
		t.Fatalf("EvaluateBatch 150k failed: %v", err)
	}
	dur150k := time.Since(start150k)
	if len(res150k) != 150000 {
		t.Fatalf("expected 150,000 results, got %d", len(res150k))
	}
	t.Logf("Guard processed 150,000 end-to-end actions in %v (%.0f ops/sec)", dur150k, 150000.0/dur150k.Seconds())

	// Verify complete 200,000 records
	startVerify200k := time.Now()
	v200k, err := store.Verify()
	if err != nil {
		t.Fatalf("audit verify 200k failed: %v", err)
	}
	durVerify200k := time.Since(startVerify200k)
	if !v200k.Valid || v200k.Checked != 200000 {
		t.Fatalf("200k audit verification failed: valid=%v checked=%d", v200k.Valid, v200k.Checked)
	}
	t.Logf("Audit hash chain 200,000 records VERIFIED in %v (%.0f events/sec).", durVerify200k, 200000.0/durVerify200k.Seconds())
}

func RuleTestPack() []policy.Rule {
	return []policy.Rule{
		{ID: "allow-src", Kind: "file", Match: []string{"src/**", "internal/**"}, Decision: policy.Allow, Reason: "source files"},
		{ID: "allow-git-commit", Kind: "shell", Match: []string{"git commit*"}, Decision: policy.Allow, Reason: "local git commit"},
		{ID: "allow-db-select", Kind: "database", Match: []string{"select *"}, Decision: policy.Allow, Reason: "read query"},
	}
}
