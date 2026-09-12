# AgentGuard

> **A local-first firewall for AI agents.** See and control what coding agents, MCP clients, and automation tools are allowed to do before they touch your machine.

AgentGuard evaluates sensitive actions against human-readable policies and returns one of three decisions: **ALLOW**, **ASK**, or **DENY**. It runs locally, keeps audit data on your machine, and requires no account or cloud service.

## Why AgentGuard?

AI agents can read files, execute shell commands, call MCP tools, use Git, and reach databases. The useful question is no longer only *"what did the agent do?"* but also *"should it have been allowed to do it?"*

```text
Codex / Claude Code / Gemini / MCP client
                  |
                  v
            AgentGuard Core
        +---------+---------+
        |         |         |
      ALLOW      ASK       DENY
        |         |         |
        +---------+---------+
                  |
          Audit + Dashboard
```

## MVP features

- Local CLI: `init`, `run`, `check`, `version`
- YAML policy engine with ordered `allow`, `ask`, `deny` rules
- Risk analysis for shell, filesystem, Git, network and database actions
- Secret-sensitive defaults (`.env`, SSH keys, PEM files)
- SQLite audit log
- Local REST API for agent/MCP adapters
- Local dashboard at `http://127.0.0.1:7788`
- No login, telemetry, external database, or hosted backend
- Docker and GitHub Actions support

## Quick start

Requirements: Go 1.23+

```bash
git clone https://github.com/Loccao102/Agent-Guard.git
cd Agent-Guard
go build -o agentguard ./cmd/agentguard

./agentguard init
./agentguard run
```

Open `http://127.0.0.1:7788`.

Try a policy decision from another terminal:

```bash
./agentguard check --kind shell --value "git push origin main"
./agentguard check --kind file --value ".env.production"
./agentguard check --kind shell --value "go test ./..."
```

Or call the local integration API:

```bash
curl -X POST http://127.0.0.1:7788/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{"agent":"codex","kind":"shell","value":"git push origin main"}'
```

Example response:

```json
{
  "decision": "ask",
  "risk": "high",
  "reason": "remote repository mutation requires approval",
  "rule_id": "git-push"
}
```

## Default policy

`agentguard init` creates `agentguard.yaml`:

```yaml
version: 1
default: ask
server:
  host: 127.0.0.1
  port: 7788
audit:
  database: .agentguard/agentguard.db
rules:
  - id: protect-secrets
    kind: file
    match: [".env*", "**/.env*", "**/*.pem", "**/.ssh/**"]
    decision: deny
    reason: sensitive file is protected

  - id: safe-tests
    kind: shell
    match: ["go test*", "dotnet test*", "npm test*"]
    decision: allow
    reason: test command is allowed

  - id: git-push
    kind: shell
    match: ["git push*"]
    decision: ask
    reason: remote repository mutation requires approval
```

Rules are evaluated in order. The first matching rule wins; otherwise the configured `default` decision is used.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/evaluate` | Evaluate + audit an action |
| `GET` | `/api/events?limit=100` | Recent audit events |
| `GET` | `/api/stats` | Dashboard counts |

Action kinds are intentionally open strings. Recommended values are `shell`, `file`, `git`, `database`, `network`, and `mcp`.

## Architecture

```text
Incoming action
      |
      v
  Normalizer
      |
      +------> Risk Analyzer
      |
      v
 Policy Engine
      |
  +---+---+
  |   |   |
allow ask deny
  |   |   |
  +---+---+
      |
      v
 SQLite Audit
      |
      v
 Local Dashboard
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for design details and extension points.

## Roadmap

- [x] Policy engine
- [x] Risk analyzer
- [x] Local audit database
- [x] REST integration API
- [x] Local dashboard
- [ ] Approval workflow with one-time/session grants
- [ ] Native MCP stdio/HTTP proxy
- [ ] Claude Code adapter
- [ ] Codex adapter
- [ ] Gemini CLI adapter
- [ ] Signed community policy packs
- [ ] Windows/macOS/Linux release binaries

## Security model

AgentGuard is currently an enforcement **decision layer**. An integration must route an action through AgentGuard before execution for that action to be enforceable. The MVP does not claim to sandbox arbitrary processes or magically intercept every command on the operating system.

Read [`SECURITY.md`](SECURITY.md) before using it around production credentials or systems.

## Contributing

Issues and pull requests are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
