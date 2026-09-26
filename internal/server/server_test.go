package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Loccao102/Agent-Guard/internal/approval"
	"github.com/Loccao102/Agent-Guard/internal/audit"
	"github.com/Loccao102/Agent-Guard/internal/config"
	"github.com/Loccao102/Agent-Guard/internal/guard"
	"github.com/Loccao102/Agent-Guard/internal/policy"
	"github.com/Loccao102/Agent-Guard/internal/risk"
)

func setupTestServer(t *testing.T) (*httptest.Server, *audit.Store) {
	rules := []policy.Rule{
		{ID: "allow-docs", Kind: "file", Match: []string{"docs/**", "*.md"}, Decision: policy.Allow, Reason: "docs"},
		{ID: "deny-secret", Kind: "file", Match: []string{".env*"}, Decision: policy.Deny, Reason: "secret"},
		{ID: "allow-git", Kind: "shell", Match: []string{"git status*"}, Decision: policy.Allow, Reason: "git"},
	}
	engine, err := policy.NewEngine(policy.Ask, rules)
	if err != nil {
		t.Fatal(err)
	}
	store, err := audit.Open(filepath.Join(t.TempDir(), "server_audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	broker := approval.New(2 * time.Minute)
	g := guard.New(engine, risk.NewAnalyzer(), store, broker)

	srv := New(config.Server{Host: "127.0.0.1", Port: 0}, g, store)
	ts := httptest.NewServer(srv.Handler)
	return ts, store
}

func TestServerHealth(t *testing.T) {
	ts, store := setupTestServer(t)
	defer ts.Close()
	defer store.Close()

	resp, err := http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestServerEvaluateAndBatch(t *testing.T) {
	ts, store := setupTestServer(t)
	defer ts.Close()
	defer store.Close()

	// 1. Single evaluation
	body, _ := json.Marshal(map[string]any{
		"agent": "test",
		"kind":  "file",
		"value": "docs/README.md",
	})
	resp, err := http.Post(ts.URL+"/api/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var res guard.Result
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.Decision != policy.Allow {
		t.Fatalf("expected allow, got %s", res.Decision)
	}

	// 2. Batch evaluation of 1,000 actions
	actions := make([]map[string]any, 1000)
	for i := 0; i < 1000; i++ {
		kind := "file"
		val := fmt.Sprintf("docs/page_%d.md", i)
		if i%2 == 0 {
			kind = "shell"
			val = "git status"
		}
		actions[i] = map[string]any{
			"agent": "batch-tester",
			"kind":  kind,
			"value": val,
		}
	}
	batchBody, _ := json.Marshal(map[string]any{"actions": actions})
	respBatch, err := http.Post(ts.URL+"/api/evaluate/batch", "application/json", bytes.NewReader(batchBody))
	if err != nil {
		t.Fatal(err)
	}
	defer respBatch.Body.Close()
	if respBatch.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", respBatch.StatusCode)
	}
	var batchResults []guard.Result
	if err := json.NewDecoder(respBatch.Body).Decode(&batchResults); err != nil {
		t.Fatal(err)
	}
	if len(batchResults) != 1000 {
		t.Fatalf("expected 1000 results, got %d", len(batchResults))
	}

	// 3. Verify audit chain
	respVerify, err := http.Get(ts.URL + "/api/audit/verify")
	if err != nil {
		t.Fatal(err)
	}
	defer respVerify.Body.Close()
	var v audit.Verification
	if err := json.NewDecoder(respVerify.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if !v.Valid || v.Checked != 1001 {
		t.Fatalf("expected 1001 valid verified events, got valid=%v checked=%d", v.Valid, v.Checked)
	}

	// 4. Stats
	respStats, err := http.Get(ts.URL + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer respStats.Body.Close()
	var stats audit.Stats
	if err := json.NewDecoder(respStats.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if stats.Total != 1001 {
		t.Fatalf("expected stats total 1001, got %d", stats.Total)
	}
}

func TestServerAuthToken(t *testing.T) {
	rules := []policy.Rule{
		{ID: "allow-docs", Kind: "file", Match: []string{"docs/**"}, Decision: policy.Allow, Reason: "docs"},
	}
	engine, err := policy.NewEngine(policy.Ask, rules)
	if err != nil {
		t.Fatal(err)
	}
	store, err := audit.Open(filepath.Join(t.TempDir(), "server_auth_audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	broker := approval.New(2 * time.Minute)
	g := guard.New(engine, risk.NewAnalyzer(), store, broker)

	testToken := "test-secret-token-12345"
	srv := New(config.Server{Host: "127.0.0.1", Port: 0, Token: testToken}, g, store)
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	// 1. Health check is always public
	resp, err := http.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for /api/health, got %d", resp.StatusCode)
	}

	// 2. Protected endpoint without token should return 401
	resp, err = http.Get(ts.URL + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /api/stats, got %d", resp.StatusCode)
	}

	// 3. Protected endpoint with Bearer header
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/stats", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for Bearer auth, got %d", resp.StatusCode)
	}

	// 4. Protected endpoint with X-AgentGuard-Token header
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/stats", nil)
	req.Header.Set("X-AgentGuard-Token", testToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for X-AgentGuard-Token auth, got %d", resp.StatusCode)
	}

	// 5. Protected endpoint with ?token= query parameter
	resp, err = http.Get(ts.URL + "/api/stats?token=" + testToken)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for ?token= auth, got %d", resp.StatusCode)
	}
}

func TestServerSSEStream(t *testing.T) {
	rules := []policy.Rule{
		{ID: "ask-shell", Kind: "shell", Match: []string{"git push*"}, Decision: policy.Ask, Reason: "ask push"},
	}
	engine, err := policy.NewEngine(policy.Allow, rules)
	if err != nil {
		t.Fatal(err)
	}
	store, err := audit.Open(filepath.Join(t.TempDir(), "server_sse_audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	broker := approval.New(2 * time.Minute)
	g := guard.New(engine, risk.NewAnalyzer(), store, broker)

	srv := New(config.Server{Host: "127.0.0.1", Port: 0}, g, store)
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	// Connect to SSE stream
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for SSE stream, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected text/event-stream, got %s", ct)
	}

	reader := bufio.NewReader(resp.Body)
	// First line should be initial connection event
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "event: connected") {
		t.Fatalf("expected 'event: connected', got %q", line)
	}

	// Trigger an approval request to broadcast SSE event
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = g.Evaluate(context.Background(), guard.Action{
			Agent: "sse-agent",
			Kind:  "shell",
			Value: "git push origin main",
		}, false)
	}()

	received := false
	deadline := time.After(2 * time.Second)
	for !received {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for approval.created SSE event")
		default:
			l, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(l, "approval.created") {
				received = true
			}
		}
	}
}
