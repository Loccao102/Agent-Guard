package packs

import (
	"fmt"
	"github.com/Loccao102/Agent-Guard/internal/config"
	"github.com/Loccao102/Agent-Guard/internal/policy"
	"github.com/Loccao102/Agent-Guard/internal/signing"
	"gopkg.in/yaml.v3"
	"os"
	"strings"
)

type Pack struct {
	Name        string        `yaml:"name" json:"name"`
	Version     string        `yaml:"version" json:"version"`
	Description string        `yaml:"description" json:"description"`
	Rules       []policy.Rule `yaml:"rules" json:"rules"`
}

func Load(path string) (Pack, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Pack{}, err
	}
	var p Pack
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Pack{}, fmt.Errorf("parse policy pack: %w", err)
	}
	if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Version) == "" || len(p.Rules) == 0 {
		return Pack{}, fmt.Errorf("policy pack requires name, version and at least one rule")
	}
	if _, err := policy.NewEngine("ask", p.Rules); err != nil {
		return Pack{}, fmt.Errorf("invalid policy pack: %w", err)
	}
	return p, nil
}
func Install(configPath, packPath, publicKeyPath, signaturePath string) (Pack, error) {
	if signaturePath != "" || publicKeyPath != "" {
		if signaturePath == "" || publicKeyPath == "" {
			return Pack{}, fmt.Errorf("both signature and public key are required for verification")
		}
		ok, err := signing.VerifyFile(packPath, publicKeyPath, signaturePath)
		if err != nil {
			return Pack{}, err
		}
		if !ok {
			return Pack{}, fmt.Errorf("policy pack signature is invalid")
		}
	}
	p, err := Load(packPath)
	if err != nil {
		return Pack{}, err
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return Pack{}, err
	}
	ids := make(map[string]struct{}, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		ids[rule.ID] = struct{}{}
	}
	for _, rule := range p.Rules {
		if _, exists := ids[rule.ID]; exists {
			return Pack{}, fmt.Errorf("rule id %q already exists", rule.ID)
		}
		cfg.Rules = append(cfg.Rules, rule)
		ids[rule.ID] = struct{}{}
	}
	if err := config.Save(configPath, cfg); err != nil {
		return Pack{}, err
	}
	return p, nil
}
