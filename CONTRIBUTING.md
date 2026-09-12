# Contributing to AgentGuard

Thanks for helping build a safer local runtime for AI agents.

## Development

```bash
git clone https://github.com/Loccao102/Agent-Guard.git
cd Agent-Guard
go mod download
go test ./...
go run ./cmd/agentguard init
go run ./cmd/agentguard run
```

Before opening a PR:

```bash
gofmt -w .
go test ./...
go vet ./...
go build ./cmd/agentguard
```

## Good first contributions

- Add policy examples for common developer workflows.
- Add risk heuristics with tests.
- Improve dashboard accessibility and UX.
- Build an adapter for a concrete agent/tool runtime.
- Add tests around policy matching and audit persistence.

## Pull request principles

- Keep the enforcement core vendor-neutral.
- New risky behavior requires tests.
- Avoid telemetry or external network calls in the default path.
- Prefer small dependencies for the trusted core.
- Document security assumptions explicitly.
