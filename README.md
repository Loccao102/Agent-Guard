# AgentGuard

> **A local-first firewall for AI agents.** Put a policy and approval layer in front of MCP tool calls before they reach your machine, services, or data.

AgentGuard is a free, open-source runtime guard for AI-agent tooling. It evaluates sensitive actions using human-readable policies and returns one of three decisions: **ALLOW**, **ASK**, or **DENY**.

Everything runs locally. There is no AgentGuard account, hosted control plane, telemetry requirement, or cloud database.

```text
Codex / Claude Code / Gemini CLI / MCP client
                    |
                    | MCP
                    v
             AgentGuard Proxy
                    |
          +---------+---------+
          |         |         |
        ALLOW      ASK       DENY
          |         |         |
          |     Local UI      |
          |     approval      |
          +---------+---------+
                    |
                    v
             MCP server/tool
                    |
                    v
        Redacted + hash-chained audit
```

## Why AgentGuard?

Coding agents and MCP clients can increasingly invoke tools that reach repositories, APIs, databases, files, and other systems. Observability can tell you what happened after the fact. AgentGuard focuses on a different question:

> **Should this tool call be allowed to happen at all?**

A typical flow looks like this:

```text
Agent wants to call a tool
        |
        v
AgentGuard evaluates policy + risk
        |
   +----+----+
   |    |    |
 allow ask  deny
   |    |    |
   |    |    +--> return policy error
   |    |
   |    +-------> dashboard approval
   |              Allow once / Allow session / Deny
   |
   +------------> forward to MCP server
```

## AgentGuard v1

### Runtime protection

- Ordered YAML policy engine with `allow`, `ask`, and `deny`
- MCP stdio proxy with protocol-aware `tools/call` inspection
- Local approval broker with **Allow once**, **Allow session**, and **Deny**
- Fail-closed behavior when approval or AgentGuard is unavailable
- Risk analysis for common shell, file, Git, network, database, and MCP actions
- Redaction of common secret/token shapes before audit persistence

### Audit and integrity

- Local SQLite audit database
- SHA-256 hash-chained v1 audit records
- CLI and HTTP verification of the audit chain
- No remote telemetry in the default path

### Integrations

- Codex MCP registration command generator
- Claude Code MCP registration command generator
- Gemini CLI MCP registration command generator
- Generic stdio MCP proxy for other compatible clients
- Local REST API for custom integrations

### Community features

- Installable YAML policy packs
- Optional Ed25519 signing and verification for policy packs
- Example read-only MCP policy pack
- Docker support
- Cross-platform release workflow for Linux, macOS, and Windows
- Apache-2.0 license

## Quick start

Requirements for building from source: **Go 1.23+**.

```bash
git clone https://github.com/Loccao102/Agent-Guard.git
cd Agent-Guard

go build -o agentguard ./cmd/agentguard

./agentguard init
./agentguard run
```

On Windows PowerShell, run the built `agentguard.exe` instead.

Open the local dashboard:

```text
http://127.0.0.1:7788
```

The dashboard shows activity, risk levels, pending approvals, policy decisions, and audit-chain verification.

## Try the policy engine

```bash
agentguard check --kind file --value ".env.production"
agentguard check --kind shell --value "go test ./..."
agentguard check --kind shell --value "git push origin main"
```

Example response:

```json
{
  "agent": "cli",
  "decision": "ask",
  "kind": "shell",
  "reason": "remote repository mutation requires approval",
  "risk": "high",
  "rule_id": "git-push",
  "value": "git push origin main"
}
```

## Protect an MCP server

Start AgentGuard first:

```bash
agentguard run
```

Then wrap a stdio MCP server:

```bash
agentguard mcp proxy \
  --agent my-agent \
  --server my-server \
  -- my-mcp-server --stdio
```

Ordinary MCP messages pass through unchanged. Before a `tools/call` request reaches the downstream server, AgentGuard asks the local runtime for a decision.

If the decision is `ASK`, the request waits while an approval appears at `http://127.0.0.1:7788`.

## Codex, Claude Code, and Gemini CLI

AgentGuard can generate the MCP registration command for each supported client instead of editing the client's configuration automatically.

```bash
agentguard adapter codex  --name my-server -- my-mcp-server --stdio
agentguard adapter claude --name my-server -- my-mcp-server --stdio
agentguard adapter gemini --name my-server -- my-mcp-server --stdio
```

Review the generated command before running it. This keeps the integration transparent and avoids AgentGuard silently changing global tool configuration.

See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) for the full integration flow.

## Approval model

For an `ASK` decision, the dashboard offers:

| Action | Effect |
|---|---|
| **Allow once** | Permit this pending action only |
| **Allow session** | Permit the exact agent/kind/value for the current AgentGuard process session |
| **Deny** | Reject the pending action |

Session grants are memory-only. Restarting AgentGuard or clearing session grants removes them.

If approval expires or cannot be completed, AgentGuard denies the proxied action rather than silently forwarding it.

## Policy configuration

`agentguard init` creates `agentguard.yaml`.

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
    match:
      - ".env*"
      - "**/.env*"
      - "**/*.pem"
      - "**/.ssh/**"
    decision: deny
    reason: sensitive file is protected

  - id: safe-tests
    kind: shell
    match:
      - "go test*"
      - "dotnet test*"
      - "npm test*"
    decision: allow
    reason: test command is allowed

  - id: git-push
    kind: shell
    match:
      - "git push*"
    decision: ask
    reason: remote repository mutation requires approval
```

Rules are evaluated in order. The first matching rule wins. If no rule matches, `default` is used.

## Policy packs

A policy pack is a shareable YAML file containing named rules.

Install the included example:

```bash
agentguard pack install --pack policies/read-only-mcp.yaml
```

For third-party packs, you can require an Ed25519 signature:

```bash
agentguard pack install \
  --pack community-pack.yaml \
  --public-key publisher.pub \
  --signature community-pack.yaml.sig
```

### Sign a policy pack

```bash
agentguard keygen --private publisher.key --public publisher.pub
agentguard sign --file community-pack.yaml --private-key publisher.key
agentguard verify --file community-pack.yaml --public-key publisher.pub
```

Never commit the private publisher key.

## Audit integrity

AgentGuard stores audit data locally in SQLite. Common token/secret shapes are redacted before new events are persisted.

Each new v1 audit event includes the hash of the previous v1 event and its own SHA-256 hash.

Verify the chain:

```bash
agentguard audit verify
```

Or use:

```text
GET /api/audit/verify
```

This is **tamper-evident**, not tamper-proof. A hostile process with full control of your machine can replace the database or AgentGuard itself.

## Local API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Local health check |
| `POST` | `/api/evaluate` | Evaluate and audit an action |
| `GET` | `/api/approvals` | Pending approvals |
| `POST` | `/api/approvals/{id}/decision` | Resolve an approval |
| `DELETE` | `/api/session-grants` | Revoke in-memory grants |
| `GET` | `/api/events?limit=100` | Recent audit events |
| `GET` | `/api/stats` | Dashboard counters |
| `GET` | `/api/audit/verify` | Verify hash-chain integrity |

Example:

```bash
curl -X POST http://127.0.0.1:7788/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{"agent":"custom-agent","kind":"mcp","value":"docs/search {\"query\":\"AgentGuard\"}","wait":false}'
```

## Docker

```bash
docker compose up --build
```

The Docker Compose configuration only publishes AgentGuard on the host loopback interface by default.

## Security boundary

AgentGuard v1 is an enforcement layer for actions that are **explicitly routed through AgentGuard**.

The MCP proxy protects proxied MCP `tools/call` requests. It does **not** transparently intercept arbitrary processes or automatically take control of an AI agent's built-in shell/file-editing tools.

For example, configuring an AgentGuard-proxied MCP server in a coding agent does not automatically sandbox that agent's separate built-in terminal capability. Continue using the coding agent's native permission/sandbox controls for execution paths that do not pass through AgentGuard.

AgentGuard is also not an OS sandbox, EDR, container isolation boundary, or replacement for least-privilege credentials.

Read [`SECURITY.md`](SECURITY.md) before using AgentGuard around sensitive or production systems.

## Architecture

```text
                         +----------------------+
                         |   Local Dashboard    |
                         | approvals / audit UI |
                         +----------+-----------+
                                    |
                                    v
Agent / MCP client ---> MCP Proxy ---> Guard Runtime
                                      |      |
                                      |      +--> Risk Analyzer
                                      v
                                 Policy Engine
                                      |
                            +---------+---------+
                            |         |         |
                          ALLOW      ASK       DENY
                            |         |
                            |         +--> Approval Broker
                            |
                            v
                      Downstream MCP

Guard Runtime ---> redaction ---> SQLite ---> SHA-256 audit chain
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

## CLI

```text
agentguard init
agentguard run
agentguard check
agentguard mcp proxy
agentguard adapter <codex|claude|gemini>
agentguard pack install
agentguard keygen
agentguard sign
agentguard verify
agentguard audit verify
agentguard version
```

## Development

```bash
go mod tidy
go test -race ./...
go vet ./...
go build ./cmd/agentguard
```

GitHub Actions runs the same quality gates for pull requests.

## Roadmap after v1

v1 deliberately keeps the trusted core small. Good next directions include authenticated local IPC, Streamable HTTP MCP proxying, stronger OS-specific execution adapters, richer policy conditions, signed pack registries, and optional SIEM/OpenTelemetry export.

Issues and pull requests are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
