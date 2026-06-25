# Runbook: kc-admin stack

This runbook covers the **kc-admin-gateway** and **kc-admin-mcp** services.
It assumes Keycloak is reachable and that credentials are injected via environment
variables or systemd credentials.

## Prerequisites

- A Keycloak realm for admin operations (example: `example-realm`).
- A **user token** that contains the required `keycloak-admin:*` scopes.
- An **introspection client** (confidential) with permission to introspect tokens.
- A **token-exchange client** (confidential) with permission to exchange user tokens
  for Keycloak admin tokens (service account has realm-management roles).

## Gateway configuration

Required env vars:

- `KC_GATEWAY_ADMIN_BASE_URL`
- `KC_GATEWAY_INTROSPECTION_URL`
- `KC_GATEWAY_INTROSPECTION_CLIENT_ID`
- `KC_GATEWAY_INTROSPECTION_CLIENT_SECRET`
- `KC_GATEWAY_EXCHANGE_URL`
- `KC_GATEWAY_EXCHANGE_CLIENT_ID`
- `KC_GATEWAY_EXCHANGE_CLIENT_SECRET`

Optional env vars:

- `KC_GATEWAY_ALLOWED_AZP`, `KC_GATEWAY_EXPECTED_ISSUER`, `KC_GATEWAY_EXPECTED_AUDIENCE`
- `KC_GATEWAY_EXCHANGE_AUDIENCE`, `KC_GATEWAY_EXCHANGE_RESOURCE`
- `KC_GATEWAY_LOG_LEVEL`, `KC_GATEWAY_REQUEST_TIMEOUT_MS`
- `KC_GATEWAY_TLS_CERT`, `KC_GATEWAY_TLS_KEY` (enable HTTPS)
- `KC_GATEWAY_TLS_CLIENT_CA`, `KC_GATEWAY_MTLS_REQUIRED` (enforce mTLS)
- `KC_GATEWAY_AUDIT_HASH_IDENTIFIERS` (hashed identity audit)
- `KC_GATEWAY_AUDIT_HASH_SALT` (required when audit hash is enabled)
- `KC_GATEWAY_LOG_EXCHANGE_BODY` (redacted exchange error body; default false)
- `KC_GATEWAY_LOG_EXCHANGE_BODY_MAX_BYTES` (default 2048)

Systemd credentials (optional):

- `kc_gateway_tls_cert`, `kc_gateway_tls_key`
- `kc_gateway_tls_client_ca` (when mTLS is enabled)
- `kc_gateway_audit_hash_salt` (when audit hash is enabled)

Start:

```bash
KC_GATEWAY_HOST=127.0.0.1 \
KC_GATEWAY_PORT=9300 \
KC_GATEWAY_ADMIN_BASE_URL=http://127.0.0.1:8080 \
KC_GATEWAY_INTROSPECTION_URL=http://127.0.0.1:8080/realms/example-realm/protocol/openid-connect/token/introspect \
KC_GATEWAY_INTROSPECTION_CLIENT_ID=kc-admin-introspect \
KC_GATEWAY_INTROSPECTION_CLIENT_SECRET=change-me \
KC_GATEWAY_EXCHANGE_URL=http://127.0.0.1:8080/realms/example-realm/protocol/openid-connect/token \
KC_GATEWAY_EXCHANGE_CLIENT_ID=kc-admin-exchange \
KC_GATEWAY_EXCHANGE_CLIENT_SECRET=change-me \
cargo run -p kc-admin-gateway
```

Health check:

```bash
curl -sS http://127.0.0.1:9300/health
```

Gateway route surface:
- `GET /health`
- `/admin`
- `/admin/{*path}`

### Gateway audience and token exchange

Gateway-backed deployments have two audience checks that are easy to confuse:

- `KC_GATEWAY_EXPECTED_AUDIENCE` is the inbound audience the caller token must
  contain before the gateway will authorize the request.
- `KC_GATEWAY_EXCHANGE_AUDIENCE` is the optional RFC 8693 `audience` value the
  gateway asks Keycloak to issue for the exchanged downstream token.

The MCP resource audience, such as `KC_ADMIN_MCP_RESOURCE_URL`, is not a
substitute for the gateway audience unless your realm intentionally maps the
same value into caller tokens. In the common gateway pattern, the caller token
needs both the MCP resource audience for the MCP edge and a gateway audience for
the gateway hop.

Verify the configuration before rollout:

1. Introspect or decode a non-secret copy of the caller token and confirm `iss`
   matches `KC_GATEWAY_EXPECTED_ISSUER`.
2. Confirm the token `aud` list contains `KC_GATEWAY_EXPECTED_AUDIENCE`.
3. Confirm `azp` or `client_id` is included in `KC_GATEWAY_ALLOWED_AZP`.
4. If `KC_GATEWAY_EXCHANGE_AUDIENCE` is set, confirm the exchange client is
   permitted to request that audience in Keycloak.
5. If `KC_GATEWAY_EXCHANGE_RESOURCE` is set, confirm it matches the downstream
   resource indicator expected by the admin API path.

Troubleshooting:

- A gateway `403` before token exchange usually means issuer, audience, scopes,
  roles, or `azp` did not pass the inbound gateway checks.
- A token-exchange failure after the inbound checks usually means the exchange
  client, requested audience, requested resource, or service-account roles are
  not permitted for the RFC 8693 exchange.
- Capture `x-request-id` from the response and search gateway auth logs for the
  same request ID and auth reason bucket before changing realm settings.

## MCP configuration

Required env vars:

- `KC_ADMIN_MCP_INTROSPECTION_URL`
- `KC_ADMIN_MCP_INTROSPECTION_CLIENT_ID`
- `KC_ADMIN_MCP_INTROSPECTION_CLIENT_SECRET`
- `KC_ADMIN_MCP_GATEWAY_URL`

Optional env vars:

- `KC_ADMIN_MCP_ALLOWED_AZP`, `KC_ADMIN_MCP_ALLOWED_CLIENT_IDS`
- `KC_ADMIN_MCP_BUILD_PRODUCTION` (set `true` to require caller allowlists unless break-glass is enabled)
- `KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS` (break-glass override; keep `false` in production)
- `KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS_REASON` (required when break-glass override is enabled)
- `KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS_TTL_S` (required positive TTL when break-glass override is enabled)
- `KC_ADMIN_MCP_AUDIENCE`, `KC_ADMIN_MCP_ISSUER`
- `KC_ADMIN_MCP_ROLE_READ`, `KC_ADMIN_MCP_ROLE_WRITE` (defaults: `kc-admin:read`, `kc-admin:write`)
- `KC_ADMIN_MCP_ENABLE_SECRET_TOOLS` (default: false)
- `KC_ADMIN_MCP_MTLS_MODE` (`disabled`, `native`, `proxy`)
- `KC_ADMIN_MCP_MTLS_CLIENT_CERT_HEADER` (proxy mode header name)
- `KC_ADMIN_MCP_TLS_CERT`, `KC_ADMIN_MCP_TLS_KEY` (enable HTTPS)
- `KC_ADMIN_MCP_TLS_CLIENT_CA` (required for native mTLS)
- `KC_ADMIN_MCP_GATEWAY_TLS_CA`
- `KC_ADMIN_MCP_GATEWAY_TLS_CERT`, `KC_ADMIN_MCP_GATEWAY_TLS_KEY`

Systemd credentials (optional):

- `kc_admin_mcp_gateway_tls_ca`
- `kc_admin_mcp_gateway_tls_cert`, `kc_admin_mcp_gateway_tls_key`
- `kc_admin_mcp_tls_cert`, `kc_admin_mcp_tls_key`, `kc_admin_mcp_tls_client_ca`
- `kc_admin_mcp_introspection_client_secret`

Start:

```bash
KC_ADMIN_MCP_BIND=127.0.0.1:9400 \
KC_ADMIN_MCP_RESOURCE_URL=http://127.0.0.1:9400/mcp \
KC_ADMIN_MCP_RESOURCE_METADATA_URL=http://127.0.0.1:9400/.well-known/oauth-protected-resource/mcp \
KC_ADMIN_MCP_AUTH_MODE=introspection \
KC_ADMIN_MCP_INTROSPECTION_URL=http://127.0.0.1:8080/realms/example-realm/protocol/openid-connect/token/introspect \
KC_ADMIN_MCP_INTROSPECTION_CLIENT_ID=kc-admin-mcp \
KC_ADMIN_MCP_INTROSPECTION_CLIENT_SECRET=change-me \
KC_ADMIN_MCP_GATEWAY_URL=http://127.0.0.1:9300 \
KEYCLOAK_URL=http://127.0.0.1:8080 \
KEYCLOAK_ADMIN_REALM=example-realm \
KEYCLOAK_ADMIN_CLIENT_ID=kc-admin-introspect \
cargo run -p kc-admin-mcp
```

Resource metadata:

```bash
curl -sS http://127.0.0.1:9400/.well-known/oauth-protected-resource/mcp
```

Local HTTPS + native mTLS (example):

```bash
KC_ADMIN_MCP_BIND=127.0.0.1:9443 \
KC_ADMIN_MCP_RESOURCE_URL=https://127.0.0.1:9443/mcp \
KC_ADMIN_MCP_RESOURCE_METADATA_URL=https://127.0.0.1:9443/.well-known/oauth-protected-resource/mcp \
KC_ADMIN_MCP_TLS_CERT=/path/to/server.crt \
KC_ADMIN_MCP_TLS_KEY=/path/to/server.key \
KC_ADMIN_MCP_TLS_CLIENT_CA=/path/to/ca.crt \
KC_ADMIN_MCP_MTLS_MODE=native \
KC_ADMIN_MCP_AUTH_MODE=introspection \
KC_ADMIN_MCP_INTROSPECTION_URL=https://keycloak.example/realms/example-realm/protocol/openid-connect/token/introspect \
KC_ADMIN_MCP_INTROSPECTION_CLIENT_ID=kc-admin-mcp \
KC_ADMIN_MCP_INTROSPECTION_CLIENT_SECRET=change-me \
KC_ADMIN_MCP_GATEWAY_URL=http://127.0.0.1:9300 \
KEYCLOAK_URL=https://keycloak.example \
KEYCLOAK_ADMIN_REALM=example-realm \
KEYCLOAK_ADMIN_CLIENT_ID=kc-admin-introspect \
cargo run -p kc-admin-mcp
```

## Audit + logging

- MCP audit log: `KC_ADMIN_MCP_AUDIT_LOG_PATH` (JSONL) and `KC_ADMIN_MCP_AUDIT_MAX` (ring buffer).
- Audit rotation: `KC_ADMIN_MCP_AUDIT_LOG_MAX_BYTES` + `KC_ADMIN_MCP_AUDIT_LOG_MAX_FILES`.
- Gateway logging is structured JSON via `tracing`.

## Troubleshooting

- **401 Unauthorized**: token missing/expired or failed introspection.
- **403 Forbidden**: token lacks scopes or required roles.
- **Request ID**: capture `x-request-id` from responses to correlate logs.

See `docs/SAFETY_CHECKLIST.md` for security guardrails and `docs/TEST_PLAN.md`
for test execution guidance.

For provenance/test-gate design and startup pass/fail semantics, see
`docs/provenance-test-gate-design.md`.
