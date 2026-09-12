package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Loccao102/Agent-Guard/internal/audit"
	"github.com/Loccao102/Agent-Guard/internal/config"
	"github.com/Loccao102/Agent-Guard/internal/policy"
	"github.com/Loccao102/Agent-Guard/internal/risk"
	"github.com/Loccao102/Agent-Guard/internal/server"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "init":
		initCommand(os.Args[2:])
	case "run":
		runCommand(os.Args[2:])
	case "check":
		checkCommand(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("AgentGuard", version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`AgentGuard - local-first firewall for AI agents

Usage:
  agentguard init [--force]
  agentguard run [--config agentguard.yaml]
  agentguard check --kind shell --value "git push origin main" [--config agentguard.yaml]
  agentguard version`)
}

func initCommand(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite an existing config")
	path := fs.String("config", "agentguard.yaml", "config path")
	_ = fs.Parse(args)

	if !*force {
		if _, err := os.Stat(*path); err == nil {
			log.Fatalf("%s already exists (use --force to overwrite)", *path)
		}
	}
	if err := os.WriteFile(*path, []byte(config.DefaultYAML), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("created %s\n", *path)
}

func runCommand(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	path := fs.String("config", "agentguard.yaml", "config path")
	_ = fs.Parse(args)

	cfg, err := config.Load(*path)
	if err != nil {
		log.Fatal(err)
	}
	engine, err := policy.NewEngine(cfg.Default, cfg.Rules)
	if err != nil {
		log.Fatal(err)
	}
	store, err := audit.Open(cfg.Audit.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	srv := server.New(cfg.Server, engine, risk.NewAnalyzer(), store)
	log.Printf("AgentGuard dashboard: http://%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Fatal(srv.ListenAndServe())
}

func checkCommand(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := fs.String("config", "agentguard.yaml", "config path")
	kind := fs.String("kind", "", "action kind")
	value := fs.String("value", "", "action value")
	agent := fs.String("agent", "cli", "agent name")
	_ = fs.Parse(args)
	if *kind == "" || *value == "" {
		log.Fatal("--kind and --value are required")
	}

	cfg, err := config.Load(*path)
	if err != nil {
		log.Fatal(err)
	}
	engine, err := policy.NewEngine(cfg.Default, cfg.Rules)
	if err != nil {
		log.Fatal(err)
	}
	decision := engine.Evaluate(*kind, *value)
	riskResult := risk.NewAnalyzer().Analyze(*kind, *value)
	out := map[string]any{
		"agent": *agent, "kind": *kind, "value": *value,
		"decision": decision.Decision, "rule_id": decision.RuleID,
		"reason": decision.Reason, "risk": riskResult.Level,
		"risk_reasons": riskResult.Reasons,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
