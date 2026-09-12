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

	"github.com/Loccao102/Agent-Guard/internal/approval"
	"github.com/Loccao102/Agent-Guard/internal/audit"
	"github.com/Loccao102/Agent-Guard/internal/config"
	"github.com/Loccao102/Agent-Guard/internal/guard"
)

//go:embed web/*
var webFS embed.FS

type API struct{ guard *guard.Guard; store *audit.Store; broker *approval.Broker }
type evaluateRequest struct{ Agent string `json:"agent"`; Kind string `json:"kind"`; Value string `json:"value"`; Meta map[string]string `json:"meta,omitempty"`; Wait bool `json:"wait"` }
type approvalDecisionRequest struct{ Decision string `json:"decision"`; Remember bool `json:"remember"` }

func New(cfg config.Server,g *guard.Guard,store *audit.Store)*http.Server{
	api:=&API{guard:g,store:store,broker:g.Broker()};mux:=http.NewServeMux()
	mux.HandleFunc("GET /api/health",api.health);mux.HandleFunc("POST /api/evaluate",api.evaluate);mux.HandleFunc("GET /api/events",api.events);mux.HandleFunc("GET /api/stats",api.stats);mux.HandleFunc("GET /api/audit/verify",api.verifyAudit);mux.HandleFunc("GET /api/approvals",api.approvals);mux.HandleFunc("POST /api/approvals/{id}/decision",api.resolveApproval);mux.HandleFunc("DELETE /api/session-grants",api.clearSessionGrants)
	static,_:=fs.Sub(webFS,"web");mux.Handle("/",http.FileServer(http.FS(static)))
	return &http.Server{Addr:fmt.Sprintf("%s:%d",cfg.Host,cfg.Port),Handler:securityHeaders(mux),ReadHeaderTimeout:5*time.Second,ReadTimeout:3*time.Minute,WriteTimeout:3*time.Minute,IdleTimeout:60*time.Second}
}
func(a *API)health(w http.ResponseWriter,_ *http.Request){writeJSON(w,http.StatusOK,map[string]any{"status":"ok","local":true,"version":"1"})}
func(a *API)evaluate(w http.ResponseWriter,r *http.Request){var req evaluateRequest;dec:=json.NewDecoder(http.MaxBytesReader(w,r.Body,2<<20));dec.DisallowUnknownFields();if err:=dec.Decode(&req);err!=nil{writeJSON(w,http.StatusBadRequest,map[string]string{"error":"invalid JSON body"});return};req.Agent=strings.TrimSpace(req.Agent);req.Kind=strings.TrimSpace(req.Kind);req.Value=strings.TrimSpace(req.Value);if req.Agent==""{req.Agent="unknown"};if req.Kind==""||req.Value==""{writeJSON(w,http.StatusBadRequest,map[string]string{"error":"kind and value are required"});return};result,err:=a.guard.Evaluate(r.Context(),guard.Action{Agent:req.Agent,Kind:req.Kind,Value:req.Value,Meta:req.Meta},req.Wait);if err!=nil{writeJSON(w,http.StatusInternalServerError,map[string]string{"error":"failed to evaluate action"});return};writeJSON(w,http.StatusOK,result)}
func(a *API)events(w http.ResponseWriter,r *http.Request){limit,_:=strconv.Atoi(r.URL.Query().Get("limit"));events,err:=a.store.List(limit);if err!=nil{writeJSON(w,http.StatusInternalServerError,map[string]string{"error":"failed to list events"});return};writeJSON(w,http.StatusOK,events)}
func(a *API)stats(w http.ResponseWriter,_ *http.Request){stats,err:=a.store.Stats();if err!=nil{writeJSON(w,http.StatusInternalServerError,map[string]string{"error":"failed to load stats"});return};writeJSON(w,http.StatusOK,stats)}
func(a *API)verifyAudit(w http.ResponseWriter,_ *http.Request){result,err:=a.store.Verify();if err!=nil{writeJSON(w,http.StatusInternalServerError,map[string]string{"error":"failed to verify audit chain"});return};writeJSON(w,http.StatusOK,result)}
func(a *API)approvals(w http.ResponseWriter,_ *http.Request){writeJSON(w,http.StatusOK,a.broker.List())}
func(a *API)resolveApproval(w http.ResponseWriter,r *http.Request){id:=strings.TrimSpace(r.PathValue("id"));if id==""{writeJSON(w,http.StatusBadRequest,map[string]string{"error":"approval id is required"});return};var req approvalDecisionRequest;dec:=json.NewDecoder(http.MaxBytesReader(w,r.Body,32<<10));dec.DisallowUnknownFields();if err:=dec.Decode(&req);err!=nil{writeJSON(w,http.StatusBadRequest,map[string]string{"error":"invalid JSON body"});return};if err:=a.broker.Resolve(id,strings.ToLower(strings.TrimSpace(req.Decision)),req.Remember);err!=nil{status:=http.StatusBadRequest;if err==approval.ErrNotFound{status=http.StatusNotFound};writeJSON(w,status,map[string]string{"error":err.Error()});return};writeJSON(w,http.StatusOK,map[string]any{"ok":true})}
func(a *API)clearSessionGrants(w http.ResponseWriter,_ *http.Request){a.broker.RevokeSessionGrants();writeJSON(w,http.StatusOK,map[string]any{"ok":true})}
func writeJSON(w http.ResponseWriter,status int,v any){w.Header().Set("Content-Type","application/json; charset=utf-8");w.WriteHeader(status);_=json.NewEncoder(w).Encode(v)}
func securityHeaders(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("X-Frame-Options","DENY");w.Header().Set("Referrer-Policy","no-referrer");w.Header().Set("Cache-Control","no-store");w.Header().Set("Cross-Origin-Resource-Policy","same-origin");w.Header().Set("Content-Security-Policy","default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'");next.ServeHTTP(w,r)})}
