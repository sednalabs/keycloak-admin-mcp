# keycloak-admin-mcp

Keycloak Admin MCP server with a required security gateway.

This workspace ships two Rust services:
- `kc-admin-mcp` — MCP server (scope/role gating + tool surface).
- `kc-admin-gateway` — security gateway (introspection + RFC 8693 exchange + audit).

The gateway is a required internal component; it isolates Keycloak admin credentials and
centralizes policy enforcement.

Security guidance lives in `SECURITY.md`, including edge‑hardening and token‑handling
principles intended to age well in open‑source usage.

Operational docs:
- `docs/RUNBOOK.md`
- `docs/SAFETY_CHECKLIST.md`
- `docs/TEST_PLAN.md`
- `docs/delegated-admin-exchange-design.md`
- `docs/provenance-test-gate-design.md`

## License

Apache-2.0. See `LICENSE`.

## Workspace

```bash
cargo build
```

## Structure

```
kc-admin-gateway/
kc-admin-mcp/
```
