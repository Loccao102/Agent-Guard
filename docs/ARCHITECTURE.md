# AgentGuard architecture

AgentGuard v1 is a local-first enforcement runtime for AI-agent tool calls. The trusted core is deliberately small: policy evaluation, risk classification, approvals, MCP forwarding decisions, and local audit persistence.

## Runtime overview

```text
                       Local Dashboard
                    approvals / audit / stats
                              |
                              v
+----------------+      +-----+------+       +------------------+
| Coding agent / | MCP  | AgentGuard | MCP   | Downstream stdio |
| MCP client     +----->+ MCP proxy  +------>+ MCP server       |
+----------------+      +-----+------+       +------------------+
                              |
                              v
                         Guard Runtime
                        /      |       \
                       v       v        v
                  Policy    Risk     Approval
                  Engine   Analyzer    Broker
                       \       |        /
                        +------+-------+
                               |
                               v
                         Audit Store
                      redaction + SQLite
                       SHA-256 hash chain
```

## Package boundaries

### `internal/policy`

Compiles ordered YAML rules and produces one of `allow`, `ask`, or `deny`. The first matching rule wins; otherwise the configured default decision is returned. Features pre-compiled fast-path string matchers (`exact`, `prefix`, `suffix`, `any`) delivering >1.6M evals/sec, and structured deep JSON argument inspection (`rule.Args`).

The policy engine is intentionally unaware of MCP, HTTP, SQLite, or individual agent vendors.

### `internal/risk`

Adds an independent risk classification and human-readable reasons. Risk does not silently override policy in v1; it gives policy decisions and approvals useful context.

### `internal/approval`

Owns pending approvals and in-memory session grants. Approval state is intentionally process-local. A restart clears session grants. Provides an `OnEvent` observer pattern to broadcast approval creation and resolution to subscribers.

### `internal/guard`

Coordinates policy, risk, approval, and audit behavior. Integrations should use the guard runtime instead of duplicating ALLOW/ASK/DENY logic. Supports bulk batch evaluation via `EvaluateBatch`.

### `internal/mcp`

Contains the protocol-aware stdio boundary. It forwards normal MCP messages, inspects `tools/call`, parses tool arguments, asks AgentGuard for a decision, and only forwards permitted calls.

The proxy is fail-closed when AgentGuard cannot provide a decision.

### `internal/client`

Small HTTP client used by local integrations to ask the running AgentGuard instance for decisions, with support for authentication tokens.

### `internal/adapters`

Generates transparent registration commands for Codex, Claude Code, and Gemini CLI. The adapter command generator does not automatically mutate global agent configuration.

### `internal/audit`

Persists local events in SQLite using optimized WAL mode and memory caching. Before storage, common secret/token patterns are redacted. New records are linked with SHA-256 hashes with in-memory `lastHash` mutex caching and chunked batch persistence (`RecordBatch`), maintaining high throughput (>20,000 writes/sec) and chain integrity verification (>150,000 events/sec).

### `internal/packs` and `internal/signing`

Policy packs provide a community-friendly distribution format. Ed25519 signatures can verify pack provenance before installation.

### `internal/server`

Exposes the loopback HTTP API and embeds the local dashboard. Protected with local authentication token middleware, batch evaluation endpoints, and real-time Server-Sent Events (`/api/events/stream`) pushed directly to the dashboard.

## Approval sequence

```text
MCP client          Proxy          Guard          Broker         Dashboard
    |                 |              |               |               |
    | tools/call      |              |               |               |
    +---------------->|              |               |               |
    |                 | evaluate     |               |               |
    |                 +------------->|               |               |
    |                 |              | policy = ASK  |               |
    |                 |              +-------------->|               |
    |                 |              |               | SSE push      |
    |                 |              |               |-------------->|
    |                 |              |               | pending card  |
    |                 |              |               |<--------------+
    |                 |              |               | allow / deny  |
    |                 |              |               |<--------------+
    |                 |              | resolution    |               |
    |                 |              |<--------------+               |
    |                 | result       |               |               |
    |                 |<-------------+               |               |
    | forwarded only if allowed      |               |               |
```

The waiting tool call is bounded by the approval timeout and the local HTTP request timeout. An incomplete approval resolves to a deny path rather than implicit forwarding.

## Data flow and privacy

The default installation does not require an AgentGuard-hosted service. Policies, approvals, and audit data remain on the local machine.

Tool-call values may contain sensitive information. Redaction is performed before audit persistence, but the unredacted value necessarily exists in memory while AgentGuard evaluates and forwards the request.

## Trust assumptions

AgentGuard assumes the integration path is actually used. An agent or local process that bypasses the MCP proxy is outside the enforcement boundary.

AgentGuard also assumes the host operating system, AgentGuard binary, local policy file, and local account are not already fully compromised. It is not a kernel security boundary.

See [`../SECURITY.md`](../SECURITY.md) for the full v1 security model.

## Extension points after v1

The architecture leaves room for:

- Streamable HTTP MCP transport;
- authenticated Unix-domain-socket / Windows named-pipe IPC;
- native execution adapters for selected agent runtimes;
- policy-pack registries and trust metadata;
- OpenTelemetry or SIEM audit export; and
- OS-native sandbox integration.

