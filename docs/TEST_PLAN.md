# Test Plan (kc-admin stack)

## Unit tests

Run per crate:

```bash
cd kc-admin-gateway && cargo test
cd kc-admin-mcp && cargo test
```

These cover auth guardrails, edge validation, and tool response shapes.

Provenance + startup admission coverage is included in `kc-admin-mcp` unit tests.
Targeted execution (optional):

```bash
cargo test -p kc-admin-mcp admission::tests
cargo test -p kc-admin-mcp provenance::tests
```

## Integration smoke tests

The integration tests are **opt‑in** and require running services. They skip unless
the required environment variables are provided.

### Gateway

```bash
KC_IT_GATEWAY_URL=http://127.0.0.1:9300 \
cargo test -p kc-admin-gateway --test integration_smoke
```

### MCP

```bash
KC_IT_MCP_URL=http://127.0.0.1:9400 \
cargo test -p kc-admin-mcp --test integration_smoke
```

### Optional authenticated flow (manual)

If you have a valid user token with `keycloak-admin:*` scopes:

```bash
KC_IT_MCP_URL=http://127.0.0.1:9400 \
KC_IT_TOKEN=eyJ... \
KC_IT_REALM=example-realm \
cargo test -p kc-admin-mcp --test integration_smoke -- --ignored
```

Optional policy update smoke:

- Use any MCP client to call `client_registration.policies.create` with a token
  that includes `keycloak-admin:realm:write` and the write role.
- Use any MCP client to call `client_registration.policies.update` with a token
  that includes `keycloak-admin:realm:write` and the write role.
- Use any MCP client to call `client_registration.policies.delete` with a token
  that includes `keycloak-admin:realm:write` and the write role.

### Delegated token-exchange policy (future opt-in)

The delegated-admin/token-exchange model is documented in
`docs/delegated-admin-exchange-design.md`. Before enabling an enforced delegated
mode, hosted validation should include:

- Pure policy vectors for allowed exchange, scope escalation, audience mismatch,
  unsupported `resource`, refresh-token request, unsupported actor chain, and
  missing audit binding.
- Gateway unit coverage proving route-derived scopes are the only requested
  scopes sent to the exchange decision.
- An opt-in authenticated Keycloak smoke for a confidential exchange client,
  with one allowed read route and at least one denied exchange.
- Log/audit assertions that denials include `request_id` and a stable reason
  bucket without raw tokens or secrets.

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
cargo test -p kc-admin-gateway
```

For MCP native TLS/mTLS, set:

```bash
KC_ADMIN_MCP_TLS_CERT=/path/to/server.crt \
KC_ADMIN_MCP_TLS_KEY=/path/to/server.key \
KC_ADMIN_MCP_TLS_CLIENT_CA=/path/to/ca.crt \
KC_ADMIN_MCP_MTLS_MODE=native \
cargo test -p kc-admin-mcp
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
