# AgentGuard integrations

AgentGuard v1 protects MCP tool calls by placing a local policy proxy between a coding agent and a downstream stdio MCP server.

```text
Coding agent
    |
    | MCP JSON-RPC
    v
AgentGuard MCP proxy
    |
    | policy + risk evaluation
    | ALLOW / ASK / DENY
    v
Downstream MCP server
```

For `ASK`, the MCP request waits while AgentGuard shows an approval card in the local dashboard. You can allow it once, allow the exact action for the current AgentGuard process session, or deny it. If approval cannot be completed, the proxy fails closed.

## Start AgentGuard

```bash
agentguard init
agentguard run
```

Open `http://127.0.0.1:7788`.

## Generate an agent registration command

Instead of manually composing the MCP proxy command, ask AgentGuard to generate the registration command for the client you use.

### Claude Code

```bash
agentguard adapter claude --name my-server -- my-mcp-server --stdio
```

### Codex

```bash
agentguard adapter codex --name my-server -- my-mcp-server --stdio
```

### Gemini CLI

```bash
agentguard adapter gemini --name my-server -- my-mcp-server --stdio
```

AgentGuard prints a command for the selected client. Review it, then run it yourself. The adapter generator does not edit your global agent configuration automatically.

## Run the proxy directly

Any stdio MCP client that lets you specify a command can launch AgentGuard directly:

```bash
agentguard mcp proxy \
  --agent my-agent \
  --server my-server \
  -- my-mcp-server --stdio
```

The proxy forwards ordinary MCP traffic unchanged. For JSON-RPC `tools/call` messages it constructs an action such as:

```text
my-server/search_documents {"query":"agent security"}
```

and asks the AgentGuard runtime for a decision before forwarding the call.

## Approval behavior

- `ALLOW`: forwarded immediately.
- `ASK`: waits for a dashboard decision.
- `DENY`: not forwarded; the client receives a JSON-RPC policy error.
- AgentGuard unavailable: not forwarded. v1 is fail-closed.
- `Allow session`: stores an in-memory grant for that exact agent/kind/value until AgentGuard restarts or session grants are cleared.

## What v1 does not intercept

AgentGuard is not an operating-system sandbox. A process that does not route an action through AgentGuard is outside this enforcement boundary.

In particular, an agent's own built-in shell or file-editing capabilities are **not automatically intercepted** just because the agent also has an AgentGuard-proxied MCP server configured. Protect those capabilities with the agent's native sandbox/permission controls until a dedicated AgentGuard adapter exists for that execution path.

## Policy packs

Install a local policy pack:

```bash
agentguard pack install --pack policies/read-only-mcp.yaml
```

For a pack from another publisher, verify its signature during installation:

```bash
agentguard pack install \
  --pack community-pack.yaml \
  --public-key publisher.pub \
  --signature community-pack.yaml.sig
```

Publishers can generate an Ed25519 key pair and sign packs:

```bash
agentguard keygen --private publisher.key --public publisher.pub
agentguard sign --file community-pack.yaml --private-key publisher.key
agentguard verify --file community-pack.yaml --public-key publisher.pub
```

Keep private signing keys outside the repository.

## Audit integrity

AgentGuard redacts common token/secret shapes before audit persistence. New v1 events are linked using SHA-256 hashes so accidental or direct row modification can be detected later.

```bash
agentguard audit verify
```

The audit chain is tamper-evident, not tamper-proof: an attacker who fully controls the host and database can still replace the database or application binary.
