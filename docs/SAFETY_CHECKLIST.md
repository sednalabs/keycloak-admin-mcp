# Safety Checklist (kc-admin stack)

Use this checklist whenever you add or change privileged capabilities.

## Authorization and tokens
- [ ] MCP enforces `iss`/`aud` (or introspection) and rejects invalid tokens.
- [ ] MCP requires scope + role gates for every tool.
- [ ] Gateway introspects user tokens and enforces scopes per route family.
- [ ] Gateway performs RFC 8693 exchange only when enabled and configured.
- [ ] MCP → Gateway mTLS is enabled where required and certificates are configured.
- [ ] No raw tokens are logged or forwarded to downstream systems.
- [ ] Client registration policy create/update/delete operations are scoped to the Allowed Client Scopes component and require realm write access.

## Secrets and credentials
- [ ] Admin credentials live **only** in the gateway process.
- [ ] Secrets are supplied via environment or systemd credentials.
- [ ] Secret tools are gated by `KC_ADMIN_MCP_ENABLE_SECRET_TOOLS`.

## Edge hardening
- [ ] Reject non‑RFC bearer header formats at the edge.
- [ ] Reject matrix params (`;`) in paths.
- [ ] Enforce strict URL canonicalization in gateways/proxies.
- [ ] If mTLS is required, enforce it at the MCP server (native) or via a trusted proxy with strict network isolation.

## Observability
- [ ] Audit log is enabled and rotated (if configured).
- [ ] Hashed identity audit (if enabled) uses a secret salt.
- [ ] Request IDs propagate from MCP to gateway.
- [ ] Alerts exist for repeated auth failures.

## Operational safety
- [ ] Dry‑run is default for bulk or destructive operations.
- [ ] `confirm=true` is required for destructive ops (prune, secret rotate, etc.).
- [ ] Backups exist before large updates or role changes.
