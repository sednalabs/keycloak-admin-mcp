# Source Instructions (kc-admin-gateway)

## Auth + Policy
- Introspect inbound tokens; never trust unsigned claims.
- Enforce issuer/audience/azp/exp checks on introspection responses.
- Token exchange must not escalate scopes beyond inbound token.

## Logging + Safety
- Redact tokens, secrets, and credentials in logs and errors.
- Include `request_id` and auth reason buckets in errors.
- Avoid logging request bodies for admin operations.

## Transport
- HTTP semantics only; TLS termination assumed at the edge for prod.
- Optional internal TLS/mTLS is supported for MCP → gateway links.
- Bind to localhost in dev by default.

## Modularisation
- Keep auth, exchange, and policy separated.
- Shared utilities stay minimal and testable.
