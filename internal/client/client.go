package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Loccao102/Agent-Guard/internal/guard"
	"io"
	"net/http"
	"strings"
)

type Client struct {
	Endpoint string
	HTTP     *http.Client
}

func New(endpoint string) *Client {
	return &Client{Endpoint: strings.TrimRight(endpoint, "/"), HTTP: &http.Client{}}
}

type evaluatePayload struct {
	guard.Action
	Wait bool `json:"wait"`
}

func (c *Client) Evaluate(ctx context.Context, action guard.Action, wait bool) (guard.Result, error) {
	body, err := json.Marshal(evaluatePayload{Action: action, Wait: wait})
	if err != nil {
		return guard.Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/api/evaluate", bytes.NewReader(body))
	if err != nil {
		return guard.Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return guard.Result{}, fmt.Errorf("contact AgentGuard: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return guard.Result{}, fmt.Errorf("AgentGuard returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var out guard.Result
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return guard.Result{}, err
	}
	return out, nil
}
