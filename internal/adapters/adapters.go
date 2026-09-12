package adapters

import (
	"fmt"
	"runtime"
	"strings"
)

type Options struct {
	Agent      string
	Name       string
	Endpoint   string
	Executable string
	Args       []string
}

func Render(opts Options) (string, error) {
	agent := strings.ToLower(strings.TrimSpace(opts.Agent))
	if opts.Name == "" || opts.Executable == "" {
		return "", fmt.Errorf("name and downstream command are required")
	}
	if opts.Endpoint == "" {
		opts.Endpoint = "http://127.0.0.1:7788"
	}
	proxyArgs := []string{"mcp", "proxy", "--endpoint", opts.Endpoint, "--agent", agent, "--server", opts.Name, "--", opts.Executable}
	proxyArgs = append(proxyArgs, opts.Args...)
	quoted := quoteArgs(proxyArgs)
	switch agent {
	case "claude", "claude-code":
		return fmt.Sprintf("claude mcp add %s -- agentguard %s", shellQuote(opts.Name), quoted), nil
	case "codex":
		return fmt.Sprintf("codex mcp add %s -- agentguard %s", shellQuote(opts.Name), quoted), nil
	case "gemini", "gemini-cli":
		return fmt.Sprintf("gemini mcp add %s agentguard %s", shellQuote(opts.Name), quoted), nil
	default:
		return "", fmt.Errorf("unsupported adapter %q (supported: codex, claude, gemini)", opts.Agent)
	}
}
func quoteArgs(args []string) string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		out = append(out, shellQuote(arg))
	}
	return strings.Join(out, " ")
}
func shellQuote(v string) string {
	if v == "" {
		return `""`
	}
	if runtime.GOOS == "windows" {
		if !strings.ContainsAny(v, " \t\"") {
			return v
		}
		return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
	}
	if !strings.ContainsAny(v, " \t'\"$&;|()<>*?[]{}!") {
		return v
	}
	return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'"
}
