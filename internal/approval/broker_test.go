package approval

import (
	"context"
	"testing"
	"time"
)

func TestResolveBeforeWaitIsRetained(t *testing.T) {
	b := New(time.Minute)
	req, err := b.Create("codex", "mcp", "demo/list_items {}", "low", "review", "demo-rule")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Resolve(req.ID, "allow", true); err != nil {
		t.Fatal(err)
	}
	res, err := b.Wait(context.Background(), req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != "allow" {
		t.Fatalf("unexpected resolution: %+v", res)
	}
	if !b.HasGrant("codex", "mcp", "demo/list_items {}") {
		t.Fatal("expected session grant")
	}
}

func TestRejectInvalidDecision(t *testing.T) {
	b := New(time.Minute)
	req, err := b.Create("agent", "mcp", "demo/list_items {}", "low", "review", "demo-rule")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Resolve(req.ID, "maybe", false); err == nil {
		t.Fatal("expected invalid decision error")
	}
}
