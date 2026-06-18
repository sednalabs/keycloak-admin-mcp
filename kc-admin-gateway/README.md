# kc-admin-gateway

Policy gateway between Keycloak Admin MCP and the Keycloak Admin REST API.
The gateway validates inbound user tokens via RFC 7662 introspection, enforces
scope-based access control, then performs RFC 8693 token exchange to obtain a
service token for Keycloak admin calls.

## Environment

Required:

- `KC_GATEWAY_ADMIN_BASE_URL` – Keycloak base URL (e.g. `http://127.0.0.1:8080`)
- `KC_GATEWAY_INTROSPECTION_URL`
- `KC_GATEWAY_INTROSPECTION_CLIENT_ID`
- `KC_GATEWAY_INTROSPECTION_CLIENT_SECRET`
- `KC_GATEWAY_EXCHANGE_URL`
- `KC_GATEWAY_EXCHANGE_CLIENT_ID`
- `KC_GATEWAY_EXCHANGE_CLIENT_SECRET`

Secrets can be provided via systemd credentials. When `CREDENTIALS_DIRECTORY`
is set, the gateway will read:

- `kc_gateway_introspection_client_secret`
- `kc_gateway_exchange_client_secret`
- `kc_gateway_tls_cert`
- `kc_gateway_tls_key`
- `kc_gateway_tls_client_ca`

Optional:

- `KC_GATEWAY_HOST` (default `127.0.0.1`)
- `KC_GATEWAY_PORT` (default `9300`)
- `KC_GATEWAY_LOG_LEVEL` (default `info`)
- `KC_GATEWAY_LOG_FORMAT` (default `logfmt`, options: `logfmt`, `json`, `plain`)
- `KC_GATEWAY_LOG_FILE` (optional path for combined logs)
- `KC_GATEWAY_ACCESS_LOG_FILE` (optional path for access logs)
- `KC_GATEWAY_AUTH_LOG_FILE` (optional path for auth logs)
- `KC_GATEWAY_REQUEST_TIMEOUT_MS` (default `5000`)
- `KC_GATEWAY_INTROSPECTION_AUTH_METHOD` (default `client_secret_basic`)
- `KC_GATEWAY_EXPECTED_ISSUER` (strict issuer match)
- `KC_GATEWAY_EXPECTED_AUDIENCE` (strict audience match)
- `KC_GATEWAY_ALLOWED_AZP` (comma-separated allowlist for azp/client_id)
- `KC_GATEWAY_BUILD_PRODUCTION` (set `true` to enforce production startup guards)
- `KC_GATEWAY_ALLOW_OPEN_AZP` (break-glass override for empty `KC_GATEWAY_ALLOWED_AZP` in production)
- `KC_GATEWAY_ALLOW_OPEN_AZP_REASON` (required when `KC_GATEWAY_ALLOW_OPEN_AZP=true`)
- `KC_GATEWAY_ALLOW_OPEN_AZP_TTL_S` (required positive TTL when `KC_GATEWAY_ALLOW_OPEN_AZP=true`)
- `KC_GATEWAY_EXCHANGE_AUTH_METHOD` (default `client_secret_basic`)
- `KC_GATEWAY_EXCHANGE_AUDIENCE` (optional RFC 8693 audience)
- `KC_GATEWAY_EXCHANGE_RESOURCE` (optional RFC 8707 resource)
- `KC_GATEWAY_EXCHANGE_ENABLED` (default `true`)
- `KC_GATEWAY_TLS_CERT`, `KC_GATEWAY_TLS_KEY` (enable HTTPS)
- `KC_GATEWAY_TLS_CLIENT_CA`, `KC_GATEWAY_MTLS_REQUIRED` (enforce mTLS)
- `KC_GATEWAY_AUDIT_HASH_IDENTIFIERS` (default `false`)
- `KC_GATEWAY_AUDIT_HASH_SALT` (required when hash audit is enabled)
- `KC_GATEWAY_LOG_EXCHANGE_BODY` (default `false`, redacted error body on token exchange failure)
- `KC_GATEWAY_LOG_EXCHANGE_BODY_MAX_BYTES` (default `2048`)

Audit hashing is **off by default** and requires a secret salt when enabled. Only
hashed identifiers are emitted to logs (no raw subjects or client IDs).

Production guardrails: when `KC_GATEWAY_BUILD_PRODUCTION=true`, startup requires
`KC_GATEWAY_EXPECTED_ISSUER`, `KC_GATEWAY_EXPECTED_AUDIENCE`, and non-empty
`KC_GATEWAY_ALLOWED_AZP` (unless explicit break-glass `KC_GATEWAY_ALLOW_OPEN_AZP=true`
with required reason and TTL).

## Run locally

```bash
cargo run
```

## Notes

- The gateway expects incoming requests to use Keycloak admin paths
  (e.g. `/admin/realms/{realm}/users`).
- The gateway surface is intentionally narrow: `/health`, `/admin`, and `/admin/{*path}`.
- Scope enforcement is derived from HTTP method + path family.
- Raw tokens are never logged; only request IDs are logged for correlation.
