# Changelog

All notable changes to AgentGuard are documented here.

## 1.0.0 — 2026-09-12

AgentGuard v1 turns the original local policy evaluator into a usable MCP enforcement runtime.

### Added

- MCP stdio proxy with protocol-aware `tools/call` inspection.
- Local approval workflow: Allow once, Allow session, Deny.
- Fail-closed behavior when approval or the AgentGuard runtime is unavailable.
- Codex, Claude Code, and Gemini CLI MCP registration command generators.
- Local REST client for custom integrations.
- Secret/token redaction before audit persistence.
- SHA-256 hash-chained audit records and audit verification.
- Installable YAML policy packs.
- Ed25519 key generation, policy-pack signing, and signature verification.
- Read-only MCP example policy pack.
- Cross-platform GitHub release workflow for Linux, macOS, and Windows.
- Expanded local dashboard for approvals, activity, risk, session grants, and audit verification.

### Security model

v1 enforces only actions explicitly routed through AgentGuard. The MCP proxy protects proxied MCP tool calls; it does not transparently intercept unrelated built-in shell or filesystem capabilities of coding agents and is not an operating-system sandbox.

## 0.1.0 — 2026-09-12

Initial local-first MVP with YAML policy evaluation, risk analysis, SQLite audit logging, REST API, local dashboard, Docker support, tests, CI, and project documentation.
