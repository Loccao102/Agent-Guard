package config

import (
	"fmt"
	"os"

	"github.com/Loccao102/Agent-Guard/internal/policy"
	"gopkg.in/yaml.v3"
)

type Server struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type Audit struct {
	Database string `yaml:"database"`
}

type Config struct {
	Version int           `yaml:"version"`
	Default string        `yaml:"default"`
	Server  Server        `yaml:"server"`
	Audit   Audit         `yaml:"audit"`
	Rules   []policy.Rule `yaml:"rules"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Version != 1 {
		return Config{}, fmt.Errorf("unsupported config version %d", cfg.Version)
	}
	if cfg.Server.Host == "" {
		cfg.Server.Host = "127.0.0.1"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 7788
	}
	if cfg.Audit.Database == "" {
		cfg.Audit.Database = ".agentguard/agentguard.db"
	}
	if cfg.Default == "" {
		cfg.Default = "ask"
	}
	return cfg, nil
}

const DefaultYAML = `version: 1
default: ask

server:
  host: 127.0.0.1
  port: 7788

audit:
  database: .agentguard/agentguard.db

rules:
  - id: protect-secrets
    kind: file
    match:
      - ".env*"
      - "**/.env*"
      - "**/*.pem"
      - "**/.ssh/**"
      - "**/id_rsa"
      - "**/id_ed25519"
    decision: deny
    reason: sensitive file is protected

  - id: destructive-shell
    kind: shell
    match:
      - "rm -rf*"
      - "del /f*"
      - "format *"
      - "shutdown*"
      - "reboot*"
    decision: deny
    reason: destructive system command is blocked

  - id: safe-tests
    kind: shell
    match:
      - "go test*"
      - "dotnet test*"
      - "npm test*"
      - "pnpm test*"
    decision: allow
    reason: test command is allowed

  - id: git-read
    kind: shell
    match:
      - "git status*"
      - "git diff*"
      - "git log*"
    decision: allow
    reason: read-only git command is allowed

  - id: git-push
    kind: shell
    match:
      - "git push*"
    decision: ask
    reason: remote repository mutation requires approval

  - id: package-install
    kind: shell
    match:
      - "npm install*"
      - "pnpm add*"
      - "go get*"
      - "dotnet add*"
    decision: ask
    reason: dependency changes require approval
`
