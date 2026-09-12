# Security policy

AgentGuard is security-sensitive software. Treat it as an additional local control layer, not as an operating-system sandbox, EDR product, or replacement for least-privilege credentials.

## v1 trust boundary

AgentGuard can enforce an action only when that action is routed through an AgentGuard integration.

The v1 MCP stdio proxy inspects proxied JSON-RPC `tools/call` requests before forwarding them to the downstream MCP server. Calls that bypass this proxy are outside AgentGuard's enforcement boundary.

Configuring one AgentGuard-proxied MCP server does **not** automatically intercept a coding agent's separate built-in shell, filesystem, browser, or patching capabilities. Keep the agent's native permission and sandbox controls enabled for those paths.

## Fail-closed proxy behavior

The MCP proxy does not intentionally forward a guarded tool call when:

- policy returns `deny`;
- an `ask` approval is denied;
- an approval expires or the waiting request is canceled; or
- the local AgentGuard runtime cannot be reached.

The downstream MCP process itself is still a normal local process. AgentGuard does not sandbox that process after it has been started.

## Approvals and session grants

`Allow once` resolves only the pending action.

`Allow session` stores an in-memory grant for the exact agent/kind/value tuple. It is cleared when AgentGuard restarts or when session grants are explicitly revoked.

Session grants are intentionally not persisted in v1 so a stale approval does not silently survive process restarts.

## Dashboard and local API

The dashboard binds to `127.0.0.1` by default. Do not expose it to an untrusted network without adding an authenticated transport layer.

The local API currently relies on the loopback trust boundary rather than user authentication. Other processes running as the same local user may be able to reach it.

## Audit data

Audit logs can contain command text, paths, SQL fragments, MCP server/tool names, and tool arguments. AgentGuard v1 redacts several common token and secret shapes before persistence, but redaction is heuristic and cannot guarantee that every secret format is removed.

New v1 events form a SHA-256 hash chain. `agentguard audit verify` can detect modification to chained event contents or ordering. This is tamper-evident, not tamper-proof: an attacker with full host access can replace the database, binary, or entire chain.

Protect `.agentguard/` using normal operating-system permissions and do not commit runtime databases.

## Policy packs

Policy packs are code-adjacent security configuration. Review rules before installation.

AgentGuard supports Ed25519 signatures for policy pack provenance. A valid signature proves the pack bytes were signed by the holder of the matching private key; it does **not** prove that the rules are safe or trustworthy.

Keep publisher private keys outside the repository. The default `.gitignore` excludes the conventional `publisher.key` path.

## Reporting vulnerabilities

Please do **not** publish exploitable vulnerabilities as a public issue. Use GitHub private vulnerability reporting / Security Advisory flow for this repository when available.

Useful reports include reproduction steps, affected version or commit, impact, and a minimal proof of concept.

## Security roadmap

Potential post-v1 hardening work includes:

- authenticated local IPC;
- OS-specific execution adapters and sandbox integrations;
- Streamable HTTP MCP proxy support;
- richer structured argument policies;
- external audit anchoring / SIEM export;
- signed policy-pack registry metadata; and
- fuzzing of MCP framing and policy parsing.
