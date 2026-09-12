package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Loccao102/Agent-Guard/internal/audit"
	"github.com/Loccao102/Agent-Guard/internal/config"
	"github.com/Loccao102/Agent-Guard/internal/policy"
	"github.com/Loccao102/Agent-Guard/internal/risk"
)

//go:embed web/*
var webFS embed.FS

type API struct {
	engine   *policy.Engine
	analyzer risk.Analyzer
	store    *audit.Store
}

type evaluateRequest struct {
	Agent string `json:"agent"`
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type evaluateResponse struct {
	Decision   string   `json:"decision"`
	Risk       string   `json:"risk"`
	Reason     string   `json:"reason"`
	RuleID     string   `json:"rule_id,omitempty"`
	RiskReasons []string `json:"risk_reasons"`
}

func New(cfg config.Server, engine *policy.Engine, analyzer risk.Analyzer, store *audit.Store) *http.Server {
	api := &API{engine: engine, analyzer: analyzer, store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", api.health)
	mux.HandleFunc("POST /api/evaluate", api.evaluate)
	mux.HandleFunc("GET /api/events", api.events)
	mux.HandleFunc("GET /api/stats", api.stats)

	static, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(static)))

	return &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "local": true})
}

func (a *API) evaluate(w http.ResponseWriter, r *http.Request) {
	var req evaluateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	req.Agent = strings.TrimSpace(req.Agent)
	req.Kind = strings.TrimSpace(req.Kind)
	req.Value = strings.TrimSpace(req.Value)
	if req.Agent == "" {
		req.Agent = "unknown"
	}
	if req.Kind == "" || req.Value == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind and value are required"})
		return
	}

	decision := a.engine.Evaluate(req.Kind, req.Value)
	riskResult := a.analyzer.Analyze(req.Kind, req.Value)
	e := audit.Event{
		Timestamp: time.Now().UTC(), Agent: req.Agent, Kind: req.Kind, Value: req.Value,
		Decision: decision.Decision, Risk: riskResult.Level, Reason: decision.Reason, RuleID: decision.RuleID,
	}
	if err := a.store.Record(e); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record audit event"})
		return
	}
	writeJSON(w, http.StatusOK, evaluateResponse{
		Decision: decision.Decision, Risk: riskResult.Level, Reason: decision.Reason,
		RuleID: decision.RuleID, RiskReasons: riskResult.Reasons,
	})
}

func (a *API) events(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := a.store.List(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list events"})
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (a *API) stats(w http.ResponseWriter, _ *http.Request) {
	stats, err := a.store.Stats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load stats"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}
