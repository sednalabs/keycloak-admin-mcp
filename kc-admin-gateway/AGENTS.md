# kc-admin-gateway (Rust) Instructions

## Mission
Provide a secure, least-privilege admin gateway for Keycloak. The gateway performs
token exchange/introspection, enforces scope/role policy, and audits all requests.

## Quick Start (Read First)
- Follow the **closest** `AGENTS.md` to the files you touch.
- Favor least-privilege defaults; never allow scope escalation.
- Never log secrets or raw tokens. Redact aggressively.
- Do not accept password grants in production paths.

## Which AGENTS.md to read
| Area | File | Notes |
| --- | --- | --- |
| Repo-wide default | `AGENTS.md` | Applies unless a closer file overrides it. |
| Source | `src/AGENTS.md` | Auth, transport, logging guardrails. |

## Tests by area (quick map)
| Area touched | Default tests |
| --- | --- |
| Gateway core | `cargo test` |

## Modularisation & Boundaries
- Keep modules focused; avoid god-modules.
- Dependencies should flow from HTTP → policy/auth → primitives.
- Policy enforcement lives in one place (no scattered checks).

## Security & Compliance
- Enforce aud/azp/exp/iss on inbound tokens.
- Introspection is authoritative; no offline fallback.
- Token exchange must be aud/resource-bound and logged with `request_id`.
- Include `request_id` in all error payloads and logs.

