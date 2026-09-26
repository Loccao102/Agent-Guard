package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Loccao102/Agent-Guard/internal/approval"
	"github.com/Loccao102/Agent-Guard/internal/audit"
	"github.com/Loccao102/Agent-Guard/internal/config"
	"github.com/Loccao102/Agent-Guard/internal/guard"
)

//go:embed web/*
var webFS embed.FS

type API struct {
	guard      *guard.Guard
	store      *audit.Store
	broker     *approval.Broker
	token      string
	sseMu      sync.Mutex
	sseClients map[chan []byte]struct{}
}

type evaluateRequest struct {
	Agent string            `json:"agent"`
	Kind  string            `json:"kind"`
	Value string            `json:"value"`
	Meta  map[string]string `json:"meta,omitempty"`
	Args  map[string]any    `json:"args,omitempty"`
	Wait  bool              `json:"wait"`
}

type approvalDecisionRequest struct {
	Decision string `json:"decision"`
	Remember bool   `json:"remember"`
}

func New(cfg config.Server, g *guard.Guard, store *audit.Store) *http.Server {
	api := &API{
		guard:      g,
		store:      store,
		broker:     g.Broker(),
		token:      strings.TrimSpace(cfg.Token),
		sseClients: make(map[chan []byte]struct{}),
	}

	// Subscribe to broker events and forward to SSE clients
	g.Broker().OnEvent(func(eventType string, payload any) {
		msg, err := json.Marshal(map[string]any{
			"type": eventType,
			"data": payload,
		})
		if err == nil {
			api.broadcastSSE(msg)
		}
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", api.health)
	mux.HandleFunc("GET /api/events/stream", api.streamEvents)
	mux.HandleFunc("POST /api/evaluate", api.evaluate)
	mux.HandleFunc("POST /api/evaluate/batch", api.evaluateBatch)
	mux.HandleFunc("GET /api/events", api.events)
	mux.HandleFunc("GET /api/stats", api.stats)
	mux.HandleFunc("GET /api/audit/verify", api.verifyAudit)
	mux.HandleFunc("GET /api/approvals", api.approvals)
	mux.HandleFunc("POST /api/approvals/{id}/decision", api.resolveApproval)
	mux.HandleFunc("DELETE /api/session-grants", api.clearSessionGrants)
	static, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(static)))

	handler := securityHeaders(authMiddleware(api.token, mux))
	return &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       3 * time.Minute,
		WriteTimeout:      3 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}
}

func (a *API) broadcastSSE(data []byte) {
	a.sseMu.Lock()
	defer a.sseMu.Unlock()
	for c := range a.sseClients {
		select {
		case c <- data:
		default:
		}
	}
}

func (a *API) streamEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	clientChan := make(chan []byte, 16)
	a.sseMu.Lock()
	a.sseClients[clientChan] = struct{}{}
	a.sseMu.Unlock()

	defer func() {
		a.sseMu.Lock()
		delete(a.sseClients, clientChan)
		close(clientChan)
		a.sseMu.Unlock()
	}()

	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"ok\"}\n\n")
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": keep-alive\n\n")
			flusher.Flush()
		case msg, ok := <-clientChan:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func authMiddleware(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}

		path := r.URL.Path
		// Public paths: root, static files, and health check
		if path == "/" || path == "/index.html" || path == "/api/health" || !strings.HasPrefix(path, "/api") {
			next.ServeHTTP(w, r)
			return
		}

		// Check Authorization: Bearer <token>
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") && strings.TrimPrefix(authHeader, "Bearer ") == token {
			next.ServeHTTP(w, r)
			return
		}

		// Check X-AgentGuard-Token header
		if r.Header.Get("X-AgentGuard-Token") == token {
			next.ServeHTTP(w, r)
			return
		}

		// Check ?token= query parameter (for EventSource or browser)
		if r.URL.Query().Get("token") == token {
			next.ServeHTTP(w, r)
			return
		}

		// Check cookie agentguard_token
		if cookie, err := r.Cookie("agentguard_token"); err == nil && cookie.Value == token {
			next.ServeHTTP(w, r)
			return
		}

		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "unauthorized: missing or invalid authentication token",
		})
	})
}
func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "local": true, "version": "1"})
}
func (a *API) evaluate(w http.ResponseWriter, r *http.Request) {
	var req evaluateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
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
	result, err := a.guard.Evaluate(r.Context(), guard.Action{Agent: req.Agent, Kind: req.Kind, Value: req.Value, Meta: req.Meta, Args: req.Args}, req.Wait)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to evaluate action"})
		return
	}
	a.broadcastSSE([]byte(`{"type":"action.evaluated"}`))
	writeJSON(w, http.StatusOK, result)
}

type batchEvaluateRequest struct {
	Actions []evaluateRequest `json:"actions"`
}

func (a *API) evaluateBatch(w http.ResponseWriter, r *http.Request) {
	var req batchEvaluateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if len(req.Actions) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "actions array cannot be empty"})
		return
	}
	if len(req.Actions) > 10000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "maximum 10000 actions per batch"})
		return
	}
	actions := make([]guard.Action, len(req.Actions))
	for i, item := range req.Actions {
		agent := strings.TrimSpace(item.Agent)
		if agent == "" {
			agent = "unknown"
		}
		kind := strings.TrimSpace(item.Kind)
		val := strings.TrimSpace(item.Value)
		if kind == "" || val == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("action at index %d requires kind and value", i)})
			return
		}
		actions[i] = guard.Action{Agent: agent, Kind: kind, Value: val, Meta: item.Meta, Args: item.Args}
	}
	results, err := a.guard.EvaluateBatch(r.Context(), actions)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to evaluate batch"})
		return
	}
	a.broadcastSSE([]byte(`{"type":"action.evaluated"}`))
	writeJSON(w, http.StatusOK, results)
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
func (a *API) verifyAudit(w http.ResponseWriter, _ *http.Request) {
	result, err := a.store.Verify()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify audit chain"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (a *API) approvals(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.broker.List())
}
func (a *API) resolveApproval(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "approval id is required"})
		return
	}
	var req approvalDecisionRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if err := a.broker.Resolve(id, strings.ToLower(strings.TrimSpace(req.Decision)), req.Remember); err != nil {
		status := http.StatusBadRequest
		if err == approval.ErrNotFound {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
func (a *API) clearSessionGrants(w http.ResponseWriter, _ *http.Request) {
	a.broker.RevokeSessionGrants()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}
