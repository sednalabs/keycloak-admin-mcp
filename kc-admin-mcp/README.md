# kc-admin-mcp (Rust)

Rust implementation of the Keycloak Admin MCP server. This MCP server is policy-light:
- Acts as an OAuth 2.1 resource server (introspection/JWKS).
- Enforces scopes + roles.
- Delegates all admin actions to kc-admin-gateway.
- Never embeds Keycloak admin credentials.

## Run locally

```bash
KC_ADMIN_MCP_BIND=127.0.0.1:9400 \
KC_ADMIN_MCP_GATEWAY_URL=http://127.0.0.1:9300 \
KC_ADMIN_MCP_RESOURCE_URL=http://127.0.0.1:9400/mcp \
KC_ADMIN_MCP_RESOURCE_METADATA_URL=http://127.0.0.1:9400/.well-known/oauth-protected-resource/mcp \
KC_ADMIN_MCP_AUTH_MODE=introspection \
KC_ADMIN_MCP_INTROSPECTION_URL=http://127.0.0.1:8080/realms/example-realm/protocol/openid-connect/token/introspect \
KC_ADMIN_MCP_INTROSPECTION_CLIENT_ID=kc-admin-mcp \
KC_ADMIN_MCP_INTROSPECTION_CLIENT_SECRET=change-me \
KEYCLOAK_URL=http://127.0.0.1:8080 \
KEYCLOAK_ADMIN_REALM=example-realm \
KEYCLOAK_ADMIN_CLIENT_ID=kc-admin-introspect \
cargo run
```

The MCP endpoint is served at `http://127.0.0.1:9400/mcp`.

## Configuration

### Core
- `KC_ADMIN_MCP_BIND`: bind address (default `127.0.0.1:9400`).
- `KC_ADMIN_MCP_RESOURCE_URL`: resource URL for audience checks.
- `KC_ADMIN_MCP_RESOURCE_METADATA_URL`: PRM URL in `WWW-Authenticate`.
- `KC_ADMIN_MCP_AUTH_SERVERS`: comma-separated list of auth servers.
- `KC_ADMIN_MCP_SCOPES_SUPPORTED`: override supported scopes.
- `KC_ADMIN_MCP_TLS_CERT`, `KC_ADMIN_MCP_TLS_KEY`: enable HTTPS for the MCP server.
- `KC_ADMIN_MCP_TLS_CLIENT_CA`: client CA bundle for native mTLS.

### Auth (resource server)
- `KC_ADMIN_MCP_AUTH_MODE`: `introspection` (default) or `jwks`.
- `KC_ADMIN_MCP_ISSUER`: expected issuer.
- `KC_ADMIN_MCP_AUDIENCE`: expected audience.
- `KC_ADMIN_MCP_ALLOWED_AZP`: allowed `azp` values (comma-separated).
- `KC_ADMIN_MCP_ALLOWED_CLIENT_IDS`: allowed client IDs (comma-separated).
- `KC_ADMIN_MCP_BUILD_PRODUCTION`: production mode toggle (`1/true` requires caller allowlists unless break-glass is enabled).
- `KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS`: break-glass override for empty caller allowlists in production (`false` by default).
- `KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS_REASON`: required when break-glass is enabled.
- `KC_ADMIN_MCP_ALLOW_OPEN_CALLER_ALLOWLISTS_TTL_S`: required positive TTL when break-glass is enabled.
- `KC_ADMIN_MCP_CLOCK_SKEW_SECONDS`: clock skew (default `30`).
- `KC_ADMIN_MCP_INTROSPECTION_URL`: introspection endpoint.
- `KC_ADMIN_MCP_INTROSPECTION_CLIENT_ID`: client id for introspection.
- `KC_ADMIN_MCP_INTROSPECTION_CLIENT_SECRET`: client secret for introspection.
- `KC_ADMIN_MCP_INTROSPECTION_AUTH_METHOD`: `client_secret_basic` (default) or `client_secret_post`.
- `KC_ADMIN_MCP_INTROSPECTION_TIMEOUT_MS`: introspection timeout (default `5000`).
- `KC_ADMIN_MCP_JWKS_URL`: required when `KC_ADMIN_MCP_AUTH_MODE=jwks`.
- `KC_ADMIN_MCP_DPOP_REQUIRED`: require DPoP (not implemented, will reject).
- `KC_ADMIN_MCP_MTLS_MODE`: `disabled` (default), `native`, or `proxy` (proxy requires header).
- `KC_ADMIN_MCP_MTLS_CLIENT_CERT_HEADER`: header name for client cert in proxy mode.
- `KC_ADMIN_MCP_MTLS_REQUIRED`: legacy alias for native mTLS when `KC_ADMIN_MCP_MTLS_MODE` is unset.

### Streamable HTTP
- `KC_ADMIN_MCP_HTTP_RESUME_MODE`: `off`, `historyless` (default), or `replay` for SSE resumption.
- `KC_ADMIN_MCP_HTTP_INITIALIZE_BODY_LIMIT_BYTES`: max body bytes read while probing sessionless
  `initialize` requests (default `16777216`).
- `KC_ADMIN_MCP_HTTP_EVENT_STORE`: `off` (default), `memory`, or `sqlite` (requires replay mode).
- `KC_ADMIN_MCP_HTTP_EVENT_STORE_PATH`: required when event store is `sqlite`.
- `KC_ADMIN_MCP_HTTP_EVENT_STORE_KEY_B64`: base64-encoded 32-byte AES-256 key for at-rest encryption.
- `KC_ADMIN_MCP_HTTP_EVENT_STORE_MAX_STREAMS`: max replay streams (default `200`).
- `KC_ADMIN_MCP_HTTP_EVENT_STORE_MAX_EVENTS`: max events per stream (default `200`).
- `KC_ADMIN_MCP_HTTP_EVENT_STORE_TTL_S`: event retention seconds (default `120`, `0` disables).
- `KC_ADMIN_MCP_HTTP_RETRY_INTERVAL_MS`: SSE retry hint when resumption enabled.

Event store encryption (sqlite replay only): set `KC_ADMIN_MCP_HTTP_EVENT_STORE_KEY_B64` to a base64
32-byte key (generate with `openssl rand -base64 32`). Existing plaintext rows still replay; encrypted
rows require the key.

### Startup Admission (test gate enforcement)
- `KC_ADMIN_MCP_STARTUP_ADMISSION_MODE`: `off`, `warn` (default for non-production), or `strict` (default for production).
- `KC_ADMIN_MCP_TEST_GATE_REQUIRED_PROFILE`: `fast` (default for non-production) or `standard` (default for production).
- `KC_ADMIN_MCP_TEST_GATE_FAST_ARTIFACT_PATH`: fast gate artifact path (default `data/test-gates/kc-admin-mcp/fast.json`).
- `KC_ADMIN_MCP_TEST_GATE_STANDARD_ARTIFACT_PATH`: standard gate artifact path (default `data/test-gates/kc-admin-mcp/standard.json`).
- `KC_ADMIN_MCP_BUILD_PRODUCTION`: production mode toggle (`1/true` enforces stricter defaults).
- `KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS`: break-glass bypass toggle (requires reason + TTL).
- `KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS_REASON`: mandatory when bypass is enabled.
- `KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS_TTL_S`: mandatory positive TTL when bypass is enabled.
- `KC_ADMIN_MCP_STARTUP_ADMISSION_ALLOW_PROD_BYPASS`: must be `1` to allow bypass in production mode.

### Build Provenance
- `KC_ADMIN_MCP_BUILD_COMPONENT`: override build component name.
- `KC_ADMIN_MCP_BUILD_SERVER_VERSION`: override server version metadata.
- `KC_ADMIN_MCP_BUILD_GIT_SHA`: override source revision.
- `KC_ADMIN_MCP_BUILD_GIT_REF`: override source reference (branch/tag).
- `KC_ADMIN_MCP_BUILD_GIT_DIRTY`: override dirty state (`true/false`).
- `KC_ADMIN_MCP_BUILD_IDENTITY_OVERRIDE`: override computed build identity.
- `KC_ADMIN_MCP_BUILD_SOURCE_DATE_EPOCH`: optional reproducible build timestamp hint.

The server publishes runtime provenance and attestation via MCP resources:
- `kc-admin://status`
- `kc-admin://attest`

## Tool schema snapshot contract

- Baseline snapshot: `spec/tool_schema_snapshot.v1.json`
- Strict contract check: `cargo test -p kc-admin-mcp tool_schema_snapshot_contract_is_stable`
- Intentional rebaseline:
  `MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test -p kc-admin-mcp tool_schema_snapshot_contract_is_stable`

### Gateway
- `KC_ADMIN_MCP_GATEWAY_URL`: gateway base URL (default `http://127.0.0.1:9300`).
- `KC_ADMIN_MCP_GATEWAY_TIMEOUT_MS`: gateway timeout (default `5000`).
- `KC_ADMIN_MCP_GATEWAY_TLS_CA`: custom CA for gateway TLS.
- `KC_ADMIN_MCP_GATEWAY_TLS_CERT`: client cert for gateway mTLS.
- `KC_ADMIN_MCP_GATEWAY_TLS_KEY`: client key for gateway mTLS.

### Keycloak metadata (observability)
These values are optional metadata surfaced by `config.get`:
- `KEYCLOAK_URL`: base URL for Keycloak (default `http://127.0.0.1:8080`).
- `KEYCLOAK_ADMIN_REALM`: realm used for admin endpoints (default `master`).
- `KEYCLOAK_ADMIN_CLIENT_ID`: client id label for observability metadata.

### Audit + metrics
- `KC_ADMIN_MCP_AUDIT_MAX`: in-memory audit ring size (default `500`).
- `KC_ADMIN_MCP_AUDIT_LOG_PATH`: optional JSONL audit log path.
- `KC_ADMIN_MCP_AUDIT_CHECKPOINT_PATH`: optional checkpoint file path.
- `KC_ADMIN_MCP_AUDIT_LOG_MAX_BYTES`: rotate audit log when size exceeds this value (0 disables).
- `KC_ADMIN_MCP_AUDIT_LOG_MAX_FILES`: number of rotated audit log files to keep (default `5`).

### Secrets
- `KC_ADMIN_MCP_ENABLE_SECRET_TOOLS`: allow secret tools (default `false`).

### Systemd credentials
If gateway TLS values are not set via env, the server will read:

- `kc_admin_mcp_gateway_tls_ca`
- `kc_admin_mcp_gateway_tls_cert`
- `kc_admin_mcp_gateway_tls_key`

If MCP TLS values are not set via env, the server will read:

- `kc_admin_mcp_tls_cert`
- `kc_admin_mcp_tls_key`
- `kc_admin_mcp_tls_client_ca`

## Tests

```bash
cargo test
```
