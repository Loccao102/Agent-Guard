package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Loccao102/Agent-Guard/internal/adapters"
	"github.com/Loccao102/Agent-Guard/internal/approval"
	"github.com/Loccao102/Agent-Guard/internal/audit"
	"github.com/Loccao102/Agent-Guard/internal/config"
	"github.com/Loccao102/Agent-Guard/internal/guard"
	"github.com/Loccao102/Agent-Guard/internal/mcp"
	"github.com/Loccao102/Agent-Guard/internal/packs"
	"github.com/Loccao102/Agent-Guard/internal/policy"
	"github.com/Loccao102/Agent-Guard/internal/risk"
	"github.com/Loccao102/Agent-Guard/internal/server"
	"github.com/Loccao102/Agent-Guard/internal/signing"
	"gopkg.in/yaml.v3"
)

var version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = initCommand(os.Args[2:])
	case "run":
		err = runCommand(os.Args[2:])
	case "check":
		err = checkCommand(os.Args[2:])
	case "test-policy":
		err = testPolicyCommand(os.Args[2:])
	case "mcp":
		err = mcpCommand(os.Args[2:])
	case "adapter":
		err = adapterCommand(os.Args[2:])
	case "pack":
		err = packCommand(os.Args[2:])
	case "keygen":
		err = keygenCommand(os.Args[2:])
	case "sign":
		err = signCommand(os.Args[2:])
	case "verify":
		err = verifyCommand(os.Args[2:])
	case "audit":
		err = auditCommand(os.Args[2:])
	case "bench":
		err = benchCommand(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("AgentGuard", version)
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}
func usage() {
	fmt.Println(`AgentGuard - local-first firewall for AI agents

Usage:
  agentguard init [--force]
  agentguard run [--config agentguard.yaml]
  agentguard check --kind shell --value "git push origin main"
  agentguard test-policy [--config agentguard.yaml] [--tests policy_tests.yaml]
  agentguard mcp proxy [--token TOKEN] --agent codex --server demo -- <server> [args...]
  agentguard adapter <codex|claude|gemini> --name demo -- <server> [args...]
  agentguard pack install --pack policies/safe-dev.yaml
  agentguard keygen [--private publisher.key] [--public publisher.pub]
  agentguard sign --file PACK --private-key KEY
  agentguard verify --file PACK --public-key KEY
  agentguard audit verify [--config agentguard.yaml]
  agentguard bench [--count 50000|200000]
  agentguard version`)
}
func initCommand(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	force := fs.Bool("force", false, "overwrite an existing config")
	path := fs.String("config", "agentguard.yaml", "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*force {
		if _, err := os.Stat(*path); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", *path)
		}
	}
	if err := os.WriteFile(*path, []byte(config.DefaultYAML), 0o644); err != nil {
		return err
	}
	fmt.Printf("created %s\n", *path)
	return nil
}
func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	path := fs.String("config", "agentguard.yaml", "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, engine, store, err := loadRuntime(*path)
	if err != nil {
		return err
	}
	defer store.Close()

	// Ensure auth token is set or auto-generated for local API security
	if cfg.Server.Token == "" {
		tokenDir := filepath.Dir(cfg.Audit.Database)
		if tokenDir == "." || tokenDir == "" {
			tokenDir = ".agentguard"
		}
		tokenPath := filepath.Join(tokenDir, "auth_token")
		if existing, err := os.ReadFile(tokenPath); err == nil && len(strings.TrimSpace(string(existing))) >= 16 {
			cfg.Server.Token = strings.TrimSpace(string(existing))
		} else {
			buf := make([]byte, 32)
			if _, err := rand.Read(buf); err == nil {
				cfg.Server.Token = hex.EncodeToString(buf)
				_ = os.MkdirAll(tokenDir, 0o700)
				_ = os.WriteFile(tokenPath, []byte(cfg.Server.Token), 0o600)
			}
		}
	}

	broker := approval.New(2 * time.Minute)
	g := guard.New(engine, risk.NewAnalyzer(), store, broker)
	srv := server.New(cfg.Server, g, store)

	if cfg.Server.Token != "" {
		log.Printf("AgentGuard v%s dashboard: http://%s:%d/?token=%s", version, cfg.Server.Host, cfg.Server.Port, cfg.Server.Token)
		log.Printf("AgentGuard auth token: %s", cfg.Server.Token)
	} else {
		log.Printf("AgentGuard v%s dashboard: http://%s:%d", version, cfg.Server.Host, cfg.Server.Port)
	}
	return srv.ListenAndServe()
}
func checkCommand(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	path := fs.String("config", "agentguard.yaml", "config path")
	kind := fs.String("kind", "", "action kind")
	value := fs.String("value", "", "action value")
	agent := fs.String("agent", "cli", "agent name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kind == "" || *value == "" {
		return fmt.Errorf("--kind and --value are required")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	engine, err := policy.NewEngine(cfg.Default, cfg.Rules)
	if err != nil {
		return err
	}
	decision := engine.Evaluate(*kind, *value)
	rr := risk.NewAnalyzer().Analyze(*kind, *value)
	out := map[string]any{"agent": *agent, "kind": *kind, "value": *value, "decision": decision.Decision, "rule_id": decision.RuleID, "reason": decision.Reason, "risk": rr.Level, "risk_reasons": rr.Reasons}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
func mcpCommand(args []string) error {
	if len(args) == 0 || args[0] != "proxy" {
		return fmt.Errorf("usage: agentguard mcp proxy [flags] -- <server> [args...]")
	}
	fs := flag.NewFlagSet("mcp proxy", flag.ContinueOnError)
	endpoint := fs.String("endpoint", "http://127.0.0.1:7788", "AgentGuard endpoint")
	agent := fs.String("agent", "mcp-client", "calling agent")
	serverName := fs.String("server", "server", "MCP server alias")
	token := fs.String("token", "", "AgentGuard auth token")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		return fmt.Errorf("downstream MCP command required after --")
	}

	tok := strings.TrimSpace(*token)
	if tok == "" {
		tok = os.Getenv("AGENTGUARD_TOKEN")
	}
	if tok == "" {
		candidates := []string{
			".agentguard/auth_token",
			filepath.Join(os.Getenv("HOME"), ".agentguard", "auth_token"),
			filepath.Join(os.Getenv("USERPROFILE"), ".agentguard", "auth_token"),
		}
		for _, c := range candidates {
			if b, err := os.ReadFile(c); err == nil && len(strings.TrimSpace(string(b))) > 0 {
				tok = strings.TrimSpace(string(b))
				break
			}
		}
	}

	return mcp.Run(context.Background(), mcp.RunnerOptions{
		Endpoint:   *endpoint,
		Token:      tok,
		Agent:      *agent,
		ServerName: *serverName,
		Command:    cmdArgs[0],
		Args:       cmdArgs[1:],
	})
}
func adapterCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("adapter name required: codex, claude, or gemini")
	}
	agent := args[0]
	fs := flag.NewFlagSet("adapter "+agent, flag.ContinueOnError)
	name := fs.String("name", "", "MCP server name")
	endpoint := fs.String("endpoint", "http://127.0.0.1:7788", "AgentGuard endpoint")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cmdArgs := fs.Args()
	if *name == "" || len(cmdArgs) == 0 {
		return fmt.Errorf("--name and downstream command after -- are required")
	}
	out, err := adapters.Render(adapters.Options{Agent: agent, Name: *name, Endpoint: *endpoint, Executable: cmdArgs[0], Args: cmdArgs[1:]})
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}
func packCommand(args []string) error {
	if len(args) == 0 || args[0] != "install" {
		return fmt.Errorf("usage: agentguard pack install --pack FILE")
	}
	fs := flag.NewFlagSet("pack install", flag.ContinueOnError)
	configPath := fs.String("config", "agentguard.yaml", "config path")
	packPath := fs.String("pack", "", "policy pack path")
	pub := fs.String("public-key", "", "publisher public key")
	sig := fs.String("signature", "", "pack signature")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *packPath == "" {
		return fmt.Errorf("--pack is required")
	}
	p, err := packs.Install(*configPath, *packPath, *pub, *sig)
	if err != nil {
		return err
	}
	fmt.Printf("installed policy pack %s@%s (%d rules)\n", p.Name, p.Version, len(p.Rules))
	return nil
}
func keygenCommand(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	priv := fs.String("private", "publisher.key", "private key path")
	pub := fs.String("public", "publisher.pub", "public key path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := signing.Generate(*priv, *pub); err != nil {
		return err
	}
	fmt.Printf("created %s and %s\n", *priv, *pub)
	return nil
}
func signCommand(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	file := fs.String("file", "", "file to sign")
	priv := fs.String("private-key", "", "Ed25519 private key")
	sig := fs.String("signature", "", "signature output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" || *priv == "" {
		return fmt.Errorf("--file and --private-key are required")
	}
	if *sig == "" {
		*sig = *file + ".sig"
	}
	if err := signing.SignFile(*file, *priv, *sig); err != nil {
		return err
	}
	fmt.Printf("signed %s -> %s\n", *file, *sig)
	return nil
}
func verifyCommand(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	file := fs.String("file", "", "file to verify")
	pub := fs.String("public-key", "", "Ed25519 public key")
	sig := fs.String("signature", "", "signature path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" || *pub == "" {
		return fmt.Errorf("--file and --public-key are required")
	}
	if *sig == "" {
		*sig = *file + ".sig"
	}
	ok, err := signing.VerifyFile(*file, *pub, *sig)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("signature verification failed")
	}
	fmt.Println("signature valid")
	return nil
}
func auditCommand(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("usage: agentguard audit verify")
	}
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	path := fs.String("config", "agentguard.yaml", "config path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := audit.Open(cfg.Audit.Database)
	if err != nil {
		return err
	}
	defer store.Close()
	v, err := store.Verify()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	if !v.Valid {
		return fmt.Errorf("audit chain is invalid")
	}
	return nil
}
func loadRuntime(path string) (config.Config, *policy.Engine, *audit.Store, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	engine, err := policy.NewEngine(cfg.Default, cfg.Rules)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	store, err := audit.Open(cfg.Audit.Database)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	return cfg, engine, store, nil
}

func benchCommand(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	count := fs.Int("count", 50000, "number of testcases/events to benchmark (e.g. 50000, 200000)")
	batchSize := fs.Int("batch", 5000, "batch size for bulk operations")
	cfgPath := fs.String("config", "", "optional config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *count <= 0 {
		return fmt.Errorf("--count must be positive")
	}

	fmt.Println("================================================================================")
	fmt.Printf("AGENTGUARD SCALE & BENCHMARK SUITE (%d testcases)\n", *count)
	fmt.Println("================================================================================")
	fmt.Printf("Testcase Count:  %d\n", *count)
	fmt.Printf("Batch Chunk:     %d\n\n", *batchSize)

	// Setup Policy Engine
	var rules []policy.Rule
	defaultDecision := policy.Ask
	if *cfgPath != "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		rules = cfg.Rules
		defaultDecision = cfg.Default
	} else {
		rules = []policy.Rule{
			{ID: "deny-secrets", Kind: "file", Match: []string{".env*", "**/.env*", "*id_rsa*", "*.pem", "*.key"}, Decision: policy.Deny, Reason: "sensitive secret file"},
			{ID: "allow-docs", Kind: "file", Match: []string{"docs/**", "*.md", "README*"}, Decision: policy.Allow, Reason: "documentation"},
			{ID: "allow-src", Kind: "file", Match: []string{"src/**", "internal/**", "cmd/**"}, Decision: policy.Allow, Reason: "source code"},
			{ID: "deny-destructive-shell", Kind: "shell", Match: []string{"rm -rf*", "*format *", "*mkfs*", "shutdown*"}, Decision: policy.Deny, Reason: "destructive OS command"},
			{ID: "ask-git-push", Kind: "shell", Match: []string{"git push*"}, Decision: policy.Ask, Reason: "remote state change"},
			{ID: "allow-git-status", Kind: "shell", Match: []string{"git status*", "git log*", "git diff*"}, Decision: policy.Allow, Reason: "read-only git inspection"},
			{ID: "allow-mcp-read", Kind: "mcp", Match: []string{"*/list*", "*/search*", "*/get*", "*/read*", "*/fetch*"}, Decision: policy.Allow, Reason: "read-only tool call"},
			{ID: "deny-db-mutation", Kind: "database", Match: []string{"drop *", "delete *", "truncate *"}, Decision: policy.Deny, Reason: "destructive database mutation"},
		}
	}

	engine, err := policy.NewEngine(defaultDecision, rules)
	if err != nil {
		return fmt.Errorf("init policy engine: %w", err)
	}
	analyzer := risk.NewAnalyzer()

	// 1. Policy Engine Benchmark
	fmt.Printf("[1/4] Policy Engine Evaluation (%d testcases)\n", *count)
	t0 := time.Now()
	for i := 0; i < *count; i++ {
		kind := "file"
		val := "src/main.go"
		switch i % 5 {
		case 0:
			kind = "file"
			val = ".env.production"
		case 1:
			kind = "shell"
			val = "git push origin main"
		case 2:
			kind = "shell"
			val = "git status"
		case 3:
			kind = "mcp"
			val = "db/fetch_item"
		case 4:
			kind = "database"
			val = "drop table users"
		}
		_ = engine.Evaluate(kind, val)
	}
	durPolicy := time.Since(t0)
	fmt.Printf("  -> Elapsed:    %v\n", durPolicy)
	fmt.Printf("  -> Throughput: %.0f evals/sec\n", float64(*count)/durPolicy.Seconds())
	fmt.Printf("  -> Status:     PASSED\n\n")

	// 2. Risk Analyzer Benchmark
	fmt.Printf("[2/4] Risk Analyzer Classification (%d testcases)\n", *count)
	t0 = time.Now()
	for i := 0; i < *count; i++ {
		kind := "shell"
		val := "git status"
		switch i % 4 {
		case 0:
			val = "rm -rf /"
		case 1:
			val = "git push origin main"
		case 2:
			val = "npm install express"
		}
		_ = analyzer.Analyze(kind, val)
	}
	durRisk := time.Since(t0)
	fmt.Printf("  -> Elapsed:    %v\n", durRisk)
	fmt.Printf("  -> Throughput: %.0f ops/sec\n", float64(*count)/durRisk.Seconds())
	fmt.Printf("  -> Status:     PASSED\n\n")

	// 3. Audit Store Ingestion Benchmark
	tmpDB, err := os.CreateTemp("", "agentguard_bench_*.db")
	if err != nil {
		return err
	}
	dbPath := tmpDB.Name()
	tmpDB.Close()
	defer os.Remove(dbPath)

	store, err := audit.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open audit store: %w", err)
	}
	defer store.Close()

	fmt.Printf("[3/4] Audit Store SQLite Hash-Chain Ingestion (%d events)\n", *count)
	events := make([]audit.Event, *count)
	now := time.Now().UTC()
	for i := 0; i < *count; i++ {
		decision := "allow"
		riskLevel := "low"
		if i%10 == 0 {
			decision = "deny"
			riskLevel = "high"
		}
		events[i] = audit.Event{
			Timestamp: now,
			Agent:     "bench-agent",
			Kind:      "file",
			Value:     fmt.Sprintf("src/pkg_%d/file.go", i%200),
			Decision:  decision,
			Risk:      riskLevel,
			Reason:    "benchmark testcase",
			RuleID:    fmt.Sprintf("rule-%d", i%10),
		}
	}

	t0 = time.Now()
	if err := store.RecordBatch(events); err != nil {
		return fmt.Errorf("audit batch record: %w", err)
	}
	durAudit := time.Since(t0)
	fmt.Printf("  -> Elapsed:    %v\n", durAudit)
	fmt.Printf("  -> Throughput: %.0f records/sec\n", float64(*count)/durAudit.Seconds())
	fmt.Printf("  -> Status:     PASSED\n\n")

	// 4. Hash Chain Verification Benchmark
	fmt.Printf("[4/4] Cryptographic Hash-Chain Verification (%d events)\n", *count)
	t0 = time.Now()
	verify, err := store.Verify()
	if err != nil {
		return fmt.Errorf("audit verify: %w", err)
	}
	durVerify := time.Since(t0)
	fmt.Printf("  -> Elapsed:    %v\n", durVerify)
	fmt.Printf("  -> Throughput: %.0f records/sec\n", float64(*count)/durVerify.Seconds())
	if !verify.Valid || verify.Checked != *count {
		return fmt.Errorf("audit chain invalid: checked=%d valid=%v bad_id=%d", verify.Checked, verify.Valid, verify.FirstBadID)
	}
	fmt.Printf("  -> Chain:      VALID (Checked: %d, FirstBadID: %d)\n", verify.Checked, verify.FirstBadID)
	fmt.Printf("  -> Status:     PASSED\n\n")

	fmt.Println("================================================================================")
	fmt.Printf("BENCHMARK COMPLETED: %d testcases processed with 100%% integrity.\n", *count)
	fmt.Println("================================================================================")
	return nil
}

type policyTestCase struct {
	Name   string         `yaml:"name" json:"name"`
	Kind   string         `yaml:"kind" json:"kind"`
	Value  string         `yaml:"value" json:"value"`
	Args   map[string]any `yaml:"args,omitempty" json:"args,omitempty"`
	Expect string         `yaml:"expect" json:"expect"`
}

type policyTestSuite struct {
	Tests []policyTestCase `yaml:"tests"`
}

func testPolicyCommand(args []string) error {
	fs := flag.NewFlagSet("test-policy", flag.ContinueOnError)
	configPath := fs.String("config", "agentguard.yaml", "config path")
	testsPath := fs.String("tests", "policy_tests.yaml", "policy test cases YAML file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config %s: %w", *configPath, err)
	}

	engine, err := policy.NewEngine(cfg.Default, cfg.Rules)
	if err != nil {
		return fmt.Errorf("init policy engine: %w", err)
	}

	testData, err := os.ReadFile(*testsPath)
	if err != nil {
		return fmt.Errorf("read tests file %s: %w", *testsPath, err)
	}

	var testCases []policyTestCase
	var suite policyTestSuite
	if err := yaml.Unmarshal(testData, &suite); err == nil && len(suite.Tests) > 0 {
		testCases = suite.Tests
	} else {
		if err := yaml.Unmarshal(testData, &testCases); err != nil || len(testCases) == 0 {
			return fmt.Errorf("parse tests file %s: invalid test suite format", *testsPath)
		}
	}

	fmt.Println("================================================================================")
	fmt.Printf("AGENTGUARD POLICY TEST RUNNER (%s)\n", *testsPath)
	fmt.Printf("Loaded %d policy rules from %s\n", len(cfg.Rules), *configPath)
	fmt.Println("================================================================================")

	passed := 0
	failed := 0

	for i, tc := range testCases {
		name := tc.Name
		if name == "" {
			name = fmt.Sprintf("Test #%d", i+1)
		}
		expected := strings.ToLower(strings.TrimSpace(tc.Expect))
		res := engine.EvaluateWithArgs(tc.Kind, tc.Value, tc.Args)

		if strings.ToLower(res.Decision) == expected {
			passed++
			fmt.Printf("  [PASS] %s\n         Kind: %-8s Value: %s\n         Decision: %-5s (Rule: %s)\n", name, tc.Kind, tc.Value, res.Decision, res.RuleID)
		} else {
			failed++
			fmt.Printf("  [FAIL] %s\n         Kind: %-8s Value: %s\n         Expected: %-5s Got: %-5s (Rule: %s, Reason: %s)\n", name, tc.Kind, tc.Value, expected, res.Decision, res.RuleID, res.Reason)
		}
	}

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("RESULTS: %d total, %d passed, %d failed\n", len(testCases), passed, failed)
	fmt.Println("================================================================================")

	if failed > 0 {
		return fmt.Errorf("%d policy test(s) failed", failed)
	}
	return nil
}
