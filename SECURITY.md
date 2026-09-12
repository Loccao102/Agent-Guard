# Security policy

AgentGuard is security-sensitive software and should be treated as an additional control, not as an operating-system sandbox.

## v0.1 trust boundary

The core returns enforcement decisions. The caller/adapter is responsible for routing an action through AgentGuard before executing it and for respecting `deny`/`ask` decisions. A process that bypasses AgentGuard is outside the MVP trust boundary.

The dashboard binds to `127.0.0.1` by default. Do not expose it publicly without adding authentication and transport security.

Audit logs can contain command text, paths, SQL, MCP tool names or other sensitive metadata. Protect the `.agentguard` directory with appropriate OS permissions and do not commit it.

## Reporting vulnerabilities

Please do **not** publish exploitable vulnerabilities as a public issue. Use GitHub's private vulnerability reporting / Security Advisory flow for this repository when available.

Useful reports include reproduction steps, affected version/commit, impact, and a minimal proof of concept.

## Security roadmap

- Request/result redaction
- Tamper-evident audit records
- Signed policy packs
- Explicit approval tokens
- Authenticated local IPC
- MCP protocol-aware proxy
- OS-level hardening guidance
