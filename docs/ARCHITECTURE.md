# AgentGuard architecture

## Design goals

1. **Local-first:** policies, audit logs and the dashboard work without an AgentGuard cloud account.
2. **Agent-agnostic:** the core evaluates normalized actions rather than depending on one model vendor.
3. **Fail understandable:** every decision contains a rule ID and human-readable reason.
4. **Composable:** adapters can sit in front of shell, filesystem, MCP, Git, databases or custom tools.
5. **Small trusted core:** policy evaluation and audit storage stay independent from integrations.

## Current request flow

```text
Adapter / CLI / MCP proxy (future)
              |
              | {agent, kind, value}
              v
         /api/evaluate
              |
       +------+------+
       |             |
       v             v
 Policy Engine   Risk Analyzer
       |             |
       +------+------+
              |
              v
          Decision
              |
              v
        SQLite Audit
              |
              v
     Local Dashboard/API
```

The policy decision and risk level are deliberately separate. A command can be high-risk yet explicitly allowed by a project policy, or low-risk but still require approval because no rule matched.

## Policy semantics

Rules are ordered. The first rule matching both `kind` and one `match` pattern wins.

- `allow`: the adapter may execute immediately.
- `ask`: execution should pause until an approval mechanism grants permission.
- `deny`: the adapter must not execute the action.

The MVP returns `ask` as a decision but does not yet implement a blocking approval channel. That is planned as a separate capability so adapters do not need to change when approval UX evolves.

## Integration contract

Adapters normalize provider-specific operations into:

```json
{
  "agent": "codex",
  "kind": "shell",
  "value": "git push origin main"
}
```

The response contains:

```json
{
  "decision": "ask",
  "risk": "high",
  "reason": "remote repository mutation requires approval",
  "rule_id": "git-push",
  "risk_reasons": ["repository state may be changed or lost"]
}
```

An enforcing adapter MUST obtain this decision before execution and MUST treat `deny` as non-executable. For `ask`, the current safe behavior is to stop and request human confirmation outside AgentGuard.

## Storage

SQLite is used for local audit data because it provides transactional writes, indexing, easy inspection and zero external services. The schema is intentionally narrow and can later be exported to OpenTelemetry, SIEM or JSONL.

## Future modules

### Approval broker
One-time grants, session grants, expiration and scoped approvals.

### MCP proxy
A native stdio/Streamable HTTP proxy that discovers MCP tools, normalizes each `tools/call`, evaluates it, and forwards only permitted calls.

### Native adapters
Wrappers/hooks for Codex, Claude Code, Gemini CLI and IDE agents.

### Policy packs
Signed reusable policies for Git, Docker, Kubernetes, PostgreSQL, Node.js, .NET and Go.

### Redaction
Prevent sensitive arguments/results from entering logs while preserving an auditable fingerprint.

## Non-goals for v0.1

- Kernel-level sandboxing
- Endpoint detection/response
- Antivirus behavior
- Secret vaulting
- Cloud identity management
- Automatically intercepting arbitrary processes without an adapter
