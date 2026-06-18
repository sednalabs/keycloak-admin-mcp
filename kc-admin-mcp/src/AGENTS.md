# Source Instructions (kc-admin-mcp)

## Auth + Transport
- Streamable HTTP only by default.
- Enforce OAuth 2.1 resource server checks (iss/aud/exp).
- Return `WWW-Authenticate` with `resource_metadata` on 401/403.

## Roles + Scopes
- Scopes are domain-specific (users/groups/roles/clients/realms/events/etc).
- Secret tools require both `clients:write` and `clients:secrets` plus explicit enablement.
- Write/admin tools require operator role(s).

## Logging + Safety
- Redact tokens and secrets in logs and errors.
- Include `request_id` in all errors and structured logs.
- Avoid logging request bodies for admin operations.

## Modularisation
- **Split tools by resource surface.** Group related tools into sub-modules (e.g., `clients/core.rs`, `clients/mappers.rs`).
- **Orchestration to Primitives.** Tools (orchestration) consume shared helpers and gateway logic (primitives). Primitives must not import tools.
- **Opportunistic Refactor.** When adding features to large files (e.g., `clients.rs`), prioritize splitting them into cohesive modules.
- **Shared utilities live under `src/tools/shared/`.**

