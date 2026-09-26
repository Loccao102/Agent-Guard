package audit

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditScale50kTo200k(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 50k-200k scale test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "audit_scale.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// 1. Stage 1: Ingest 50,000 events
	t.Log("Generating and recording 50,000 audit events...")
	start50k := time.Now()
	events50k := make([]Event, 50000)
	for i := 0; i < 50000; i++ {
		decision := "allow"
		risk := "low"
		if i%10 == 0 {
			decision = "deny"
			risk = "high"
		} else if i%5 == 0 {
			decision = "ask"
			risk = "medium"
		}
		events50k[i] = Event{
			Timestamp: time.Now().UTC(),
			Agent:     "bench-agent",
			Kind:      "file",
			Value:     fmt.Sprintf("src/pkg_%d/file_%d.go", i%100, i),
			Decision:  decision,
			Risk:      risk,
			Reason:    "scale test batch",
			RuleID:    fmt.Sprintf("rule-%d", i%20),
		}
	}

	if err := store.RecordBatch(events50k); err != nil {
		t.Fatalf("failed to record 50k batch: %v", err)
	}
	dur50k := time.Since(start50k)
	t.Logf("Recorded 50,000 events in %v (%.0f events/sec)", dur50k, 50000.0/dur50k.Seconds())

	// Verify 50k hash chain
	startVerify50k := time.Now()
	v50k, err := store.Verify()
	if err != nil {
		t.Fatalf("failed to verify 50k: %v", err)
	}
	durVerify50k := time.Since(startVerify50k)
	if !v50k.Valid || v50k.Checked != 50000 {
		t.Fatalf("50k verification mismatch: valid=%v checked=%d firstBad=%d", v50k.Valid, v50k.Checked, v50k.FirstBadID)
	}
	t.Logf("Verified 50,000 events in %v (%.0f events/sec) - VALID", durVerify50k, 50000.0/durVerify50k.Seconds())

	// 2. Stage 2: Ingest 150,000 more events (reaching 200,000 total)
	t.Log("Generating and recording additional 150,000 audit events (total 200k)...")
	start150k := time.Now()
	events150k := make([]Event, 150000)
	for i := 0; i < 150000; i++ {
		idx := 50000 + i
		events150k[i] = Event{
			Timestamp: time.Now().UTC(),
			Agent:     "bench-agent",
			Kind:      "shell",
			Value:     fmt.Sprintf("git commit -m 'commit #%d'", idx),
			Decision:  "allow",
			Risk:      "low",
			Reason:    "scale test batch 200k",
			RuleID:    "rule-shell",
		}
	}

	if err := store.RecordBatch(events150k); err != nil {
		t.Fatalf("failed to record 150k batch: %v", err)
	}
	dur150k := time.Since(start150k)
	t.Logf("Recorded 150,000 events in %v (%.0f events/sec)", dur150k, 150000.0/dur150k.Seconds())

	// Check Stats at 200k
	stats, err := store.Stats()
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}
	if stats.Total != 200000 {
		t.Fatalf("expected total 200,000 events, got %d", stats.Total)
	}
	t.Logf("Stats verified at 200,000 events: total=%d allowed=%d asked=%d denied=%d highRisk=%d",
		stats.Total, stats.Allowed, stats.Asked, stats.Denied, stats.HighRisk)

	// Verify complete 200,000 hash chain
	startVerify200k := time.Now()
	v200k, err := store.Verify()
	if err != nil {
		t.Fatalf("failed to verify 200k: %v", err)
	}
	durVerify200k := time.Since(startVerify200k)
	if !v200k.Valid || v200k.Checked != 200000 {
		t.Fatalf("200k verification mismatch: valid=%v checked=%d firstBad=%d", v200k.Valid, v200k.Checked, v200k.FirstBadID)
	}
	t.Logf("Verified 200,000 events in %v (%.0f events/sec) - VALID", durVerify200k, 200000.0/durVerify200k.Seconds())

	// 3. Re-open store and record 1 more event to ensure lastHash persists across sessions
	store.Close()
	store2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer store2.Close()

	if err := store2.Record(Event{
		Timestamp: time.Now().UTC(),
		Agent:     "after-reopen",
		Kind:      "mcp",
		Value:     "tools/call verify_reopen",
		Decision:  "allow",
		Risk:      "low",
		Reason:    "reopen continuity test",
	}); err != nil {
		t.Fatalf("failed to record after reopen: %v", err)
	}

	v200k1, err := store2.Verify()
	if err != nil {
		t.Fatalf("verify after reopen failed: %v", err)
	}
	if !v200k1.Valid || v200k1.Checked != 200001 {
		t.Fatalf("expected 200,001 valid events after reopen, got valid=%v checked=%d", v200k1.Valid, v200k1.Checked)
	}
	t.Log("Store successfully maintained hash chain continuity across reopen at 200,001 events.")
}

func BenchmarkRecordBatch50k(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dbPath := filepath.Join(b.TempDir(), "bench_50k.db")
		store, err := Open(dbPath)
		if err != nil {
			b.Fatal(err)
		}
		events := make([]Event, 50000)
		for j := 0; j < 50000; j++ {
			events[j] = Event{
				Timestamp: time.Now().UTC(),
				Agent:     "bench",
				Kind:      "file",
				Value:     "src/app.go",
				Decision:  "allow",
				Risk:      "low",
				Reason:    "bench",
			}
		}
		b.ResetTimer()
		if err := store.RecordBatch(events); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		store.Close()
	}
}

func BenchmarkVerify50k(b *testing.B) {
	dbPath := filepath.Join(b.TempDir(), "bench_verify_50k.db")
	store, err := Open(dbPath)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	events := make([]Event, 50000)
	for j := 0; j < 50000; j++ {
		events[j] = Event{
			Timestamp: time.Now().UTC(),
			Agent:     "bench",
			Kind:      "file",
			Value:     fmt.Sprintf("src/file_%d.go", j),
			Decision:  "allow",
			Risk:      "low",
			Reason:    "bench",
		}
	}
	if err := store.RecordBatch(events); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		v, err := store.Verify()
		if err != nil || !v.Valid || v.Checked != 50000 {
			b.Fatalf("verify failed: %+v, err=%v", v, err)
		}
	}
}
