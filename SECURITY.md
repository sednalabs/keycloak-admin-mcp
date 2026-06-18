# Security Considerations

This project deals with high‑privilege administration. The guidance below is
intended to **age well** and remain valid across Keycloak versions and edge
deployments.

## Edge parsing consistency

Authorization failures often come from **mismatched parsing** between your edge
(proxy/WAF/gateway) and the upstream service. To avoid bypasses:

- Enforce **exact** `Authorization: Bearer <token>` parsing at the edge.
  - Reject tabs, control characters, or multiple Authorization headers.
- **Reject or canonicalize** URL path matrix parameters (`;`) before routing
  or access control.
- Do not rely on path‑based proxy rules to protect admin endpoints unless the
  edge and upstream interpret paths identically.

The gateway is the recommended choke‑point for these checks. If you run a
single‑service MCP, the same checks must be enforced in its HTTP layer or proxy.

## Token handling

- Treat access tokens as **capabilities**, not identity documents.
- Require **aud/azp** validation and deny token passthrough.
- Use short‑lived access tokens and **refresh‑token rotation** (revoke‑on‑use).
- Consider **DPoP** for public clients to bind tokens to a client‑owned key.

## Least privilege

- Keep service accounts narrowly scoped.
- Separate “read‑only” and “admin” personas using explicit scopes.
- Prefer exchange‑from‑user‑token over admin password grants.
- **Tool Bundles and Dynamic Selection:** grouped tools (see `src/tools/bundles.rs`) allow an orchestrator to enable only the tool surface required for a specific task. This prevents unnecessarily broad agent access and reduces the blast radius of a compromised session.

## Logging and secrecy

- Never log raw tokens or Authorization headers.
- Emit request IDs and auth decision reasons to support audit trails.
- Optional **hashed identity audit** is available in the gateway, but it is **off by default**.
  When enabled, a secret salt is required and only hashes are recorded (no raw identifiers).
