# Test Plan (kc-admin stack)

## Unit tests

Run per crate:

```bash
cargo test --locked -p kc-admin-gateway
cargo test --locked -p kc-admin-mcp
```

These cover auth guardrails, edge validation, and tool response shapes.

Provenance + startup admission coverage is included in `kc-admin-mcp` unit tests.
Targeted execution (optional):

```bash
cargo test --locked -p kc-admin-mcp admission::tests
cargo test --locked -p kc-admin-mcp provenance::tests
```

## Integration smoke tests

The integration tests are **opt‑in** and require running services. They skip unless
the required environment variables are provided.

### Gateway

```bash
KC_IT_GATEWAY_URL=http://127.0.0.1:9300 \
cargo test --locked -p kc-admin-gateway --test integration_smoke
```

### MCP

```bash
KC_IT_MCP_URL=http://127.0.0.1:9400 \
cargo test --locked -p kc-admin-mcp --test integration_smoke
```

This smoke covers:

- PRM availability at `/.well-known/oauth-protected-resource/mcp`
- authorization-server metadata at `/.well-known/oauth-authorization-server/mcp`
- device-auth discovery publication via `device_authorization_endpoint` and the
  device-code grant type

### Optional authenticated flow (manual)

If you have a valid user token with `keycloak-admin:*` scopes:

```bash
KC_IT_MCP_URL=http://127.0.0.1:9400 \
KC_IT_TOKEN=eyJ... \
KC_IT_REALM=example-realm \
cargo test --locked -p kc-admin-mcp --test integration_smoke -- --ignored
```

### Optional device-auth acceptance (manual)

If you want to verify the headless login path end to end:

```bash
codex mcp login keycloak-admin-mcp --device-auth
```

Expected result:

- the client proceeds into device flow instead of failing with missing
  `device_authorization_endpoint`
- after login, normal read-only MCP checks can still fail with `auth.missing_roles`
  until the principal projects the configured `KC_ADMIN_MCP_ROLE_READ` value
  into the access token; the documented read-role default is `kc-admin:read`

Optional policy update smoke:

- Use any MCP client to call `client_registration.policies.create` with a token
  that includes `keycloak-admin:realm:write` and the configured
  `KC_ADMIN_MCP_ROLE_WRITE` value; the documented write-role default is
  `kc-admin:write`.
- Use any MCP client to call `client_registration.policies.update` with a token
  that includes `keycloak-admin:realm:write` and the configured
  `KC_ADMIN_MCP_ROLE_WRITE` value.
- Use any MCP client to call `client_registration.policies.delete` with a token
  that includes `keycloak-admin:realm:write` and the configured
  `KC_ADMIN_MCP_ROLE_WRITE` value.

### Optional delegated token-exchange acceptance (manual)

If `standard_token_exchange` or another delegated exchange mode is enabled, run
the negative-path vectors in `docs/delegated-admin-exchange-design.md` before
rollout. At minimum, verify denied issuer, audience, `azp`, scope, role, realm,
route-family, TTL, and replay/freshness cases fail closed with the expected
reason bucket.

### Optional mTLS (manual)

If running gateway with TLS/mTLS, provide PEMs via env or systemd credentials and
target `https://` URLs. Example (placeholders):

```bash
KC_GATEWAY_TLS_CERT=/path/to/server.crt \
KC_GATEWAY_TLS_KEY=/path/to/server.key \
KC_GATEWAY_TLS_CLIENT_CA=/path/to/ca.crt \
KC_GATEWAY_MTLS_REQUIRED=true \
KC_ADMIN_MCP_GATEWAY_TLS_CA=/path/to/ca.crt \
KC_ADMIN_MCP_GATEWAY_TLS_CERT=/path/to/client.crt \
KC_ADMIN_MCP_GATEWAY_TLS_KEY=/path/to/client.key \
cargo test --locked -p kc-admin-gateway
```

For MCP native TLS/mTLS, set:

```bash
KC_ADMIN_MCP_TLS_CERT=/path/to/server.crt \
KC_ADMIN_MCP_TLS_KEY=/path/to/server.key \
KC_ADMIN_MCP_TLS_CLIENT_CA=/path/to/ca.crt \
KC_ADMIN_MCP_MTLS_MODE=native \
cargo test --locked -p kc-admin-mcp
```

## Local Keycloak (manual)

You can run a local Keycloak instance to test token exchange and role/scopes:

```bash
docker run -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak start-dev
```

Update the service env vars to point at `http://127.0.0.1:8080`.
