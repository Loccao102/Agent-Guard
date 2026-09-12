package risk

import "strings"

type Result struct {
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
}

type Analyzer struct{}

func NewAnalyzer() Analyzer { return Analyzer{} }

func (Analyzer) Analyze(kind, value string) Result {
	kind = strings.ToLower(kind)
	v := strings.ToLower(strings.TrimSpace(value))
	level := "low"
	var reasons []string

	promote := func(next, reason string) {
		if rank(next) > rank(level) {
			level = next
		}
		reasons = append(reasons, reason)
	}

	if strings.Contains(v, ".env") || strings.Contains(v, "id_rsa") || strings.Contains(v, "id_ed25519") || strings.Contains(v, ".ssh") || strings.Contains(v, "private key") {
		promote("critical", "possible secret or private key access")
	}

	if kind == "shell" {
		critical := []string{"rm -rf", "format ", "mkfs", "shutdown", "reboot", ":(){", "diskpart"}
		for _, token := range critical {
			if strings.Contains(v, token) {
				promote("critical", "destructive operating-system command")
				break
			}
		}
		if strings.Contains(v, "git push") || strings.Contains(v, "git reset --hard") || strings.Contains(v, "git clean -f") {
			promote("high", "repository state may be changed or lost")
		}
		if strings.Contains(v, "curl ") || strings.Contains(v, "wget ") || strings.Contains(v, "invoke-webrequest") {
			promote("high", "command can transfer data over the network")
		}
		if strings.Contains(v, "npm install") || strings.Contains(v, "pnpm add") || strings.Contains(v, "pip install") || strings.Contains(v, "go get") || strings.Contains(v, "dotnet add") {
			promote("medium", "dependency graph will be modified")
		}
	}

	if kind == "database" {
		writes := []string{"insert ", "update ", "delete ", "drop ", "truncate ", "alter "}
		for _, token := range writes {
			if strings.Contains(v, token) {
				promote("high", "database mutation detected")
				break
			}
		}
	}

	if kind == "network" || kind == "mcp" {
		if strings.Contains(v, "http://") || strings.Contains(v, "https://") {
			promote("medium", "external network destination detected")
		}
	}

	if len(reasons) == 0 {
		reasons = []string{"no elevated-risk heuristic matched"}
	}
	return Result{Level: level, Reasons: reasons}
}

func rank(level string) int {
	switch level {
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 1
	}
}
