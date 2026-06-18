# kc-admin-mcp (Rust) Instructions

## Mission
Provide a secure, least-privilege MCP server for Keycloak administration. The MCP
server is policy-light: it enforces scopes/roles and delegates admin actions to the
gateway. It must never embed Keycloak admin credentials.

## Quick Start (Read First)
- Follow the **closest** `AGENTS.md` to the files you touch.
- Favor least-privilege defaults and explicit scope gating.
- Never log secrets or raw tokens. Redact aggressively.

## Which AGENTS.md to read
| Area | File | Notes |
| --- | --- |
| Repo-wide default | `AGENTS.md` | Applies unless a closer file overrides it. |
| Source | `src/AGENTS.md` | Auth, transport, and tool guardrails. |

## Tests by area (quick map)
| Area touched | Default tests |
| --- | --- |
| MCP server | `cargo test` |

## Modularisation & Boundaries
- **Avoid God-Modules**: Split by cohesive seams (domain/responsibility), not just line count.
- **Monolith Definition**: A unit that mixes responsibilities across layers (e.g., transport + business logic + gateway delegation).
- **Distributed Monolith Warning**: Avoid many small, tightly coupled modules with circular dependencies or deep import chains.
- **Rulebook Exception**: Large files are acceptable if they are single-purpose "rulebooks" (e.g., a central tool catalog with a stable facade).
- **Dependency Direction**: Dependencies must point from orchestration toward primitives (e.g., `tools` -> `shared`).
- **Refactor Posture**:
  - **Forward-first**: New work must follow the modular structure.
  - **Opportunistic retrofit**: Refactor legacy "god files" (e.g., 3k+ line `clients.rs`) when touching them for behavior.
  - **Facade-first**: Extract components behind a stable API/facade to keep refactors incremental.
- Keep tool registration centralized; keep tool bodies small.
- Tools must not import auth/transport internals.
- Shared helpers belong under `src/tools/shared/`.

## Security & Compliance
- Act as an OAuth 2.1 resource server (issuer/audience/exp checks).
- Return `WWW-Authenticate` headers with `resource_metadata`.
- Keep tool surfaces allow-listed; destructive tools must be gated by scope.

