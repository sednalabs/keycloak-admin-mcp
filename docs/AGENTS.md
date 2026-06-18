# Documentation Instructions (keycloak-admin-mcp)

## Scope
These guidelines apply to documentation under `docs/` unless a closer `AGENTS.md` is added.

## Content rules
- Keep docs concise and actionable; prefer checklists and runbooks.
- Do not include secrets, real tokens, or real user data.
- Use placeholders for URLs, client IDs, and credentials.
- If documenting auth flows, mention `request_id` and the auth reason buckets.

## Diagrams
- Use Mermaid for architecture/auth flows.
- Label nodes consistently (`Client`, `MCP`, `Gateway`, `Keycloak`).
- Keep diagrams small enough to fit on one screen where possible.

## Maintenance
- Update `docs/SAFETY_CHECKLIST.md` when adding new privileged tools.
- Update `docs/TEST_PLAN.md` when adding new critical paths.
