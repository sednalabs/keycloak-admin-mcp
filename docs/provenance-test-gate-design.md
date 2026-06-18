# Design: Provenance + Test-Gate Integration (kc-admin-mcp)

## Objective

Define the implementation contract for deterministic runtime provenance and startup
test-gate enforcement in `kc-admin-mcp`.

This document is implementation-facing and focused on pass/fail semantics.

## Scope

- Runtime provenance metadata fields and attestation surface.
- Startup admission checks against test-gate artifacts.
- Deployment flow touchpoints from build to post-restart verification.

Out of scope:

- Keycloak admin business logic/tool behavior.
- OAuth policy semantics beyond standard auth failures.

## Provenance Contract

`kc-admin-mcp` exposes fleet v2 attestation via `kc-admin://attest`.

Required core fields:

- `schema_version=2`
- `attestation.identity.server_version`
- `attestation.identity.build_identity`
- `attestation.identity.source_fingerprint`
- `attestation.source.revision`
- `attestation.source.reference`
- `attestation.source.dirty`
- `attestation.build_metadata.profile`
- `attestation.build_metadata.target`
- `attestation.build_metadata.rustc_version`
- `attestation.runtime.pid`
- `attestation.runtime.executable_path`

Unavailable/degraded signaling:

- Unknown/missing provenance values must remain present (`unknown` or `null`) and
  be mirrored in `unavailable[]`.
- Envelope `status` must be:
  - `ok` when provenance is complete and startup admission is not degraded.
  - `degraded` when provenance has unavailable fields or admission is degraded.

## Build Identity Injection

Build-time identity comes from service-local envs and canonical aliases:

- Service-local: `KC_ADMIN_MCP_BUILD_*`
- Canonical aliases: `MCP_BUILD_*`

Deterministic derivations:

- `build_identity`: `<component>@<server_version>+<revision>[-dirty]`
- `source_fingerprint`: `git:<revision>:clean|dirty`

Production policy:

- `KC_ADMIN_MCP_BUILD_PRODUCTION=1` enables stricter admission defaults.
- Production builds must provide explicit version/SHA signals or fail deterministically.

## Startup Admission Contract

Startup admission checks gate artifacts for required profile:

- Fast artifact: `KC_ADMIN_MCP_TEST_GATE_FAST_ARTIFACT_PATH`
- Standard artifact: `KC_ADMIN_MCP_TEST_GATE_STANDARD_ARTIFACT_PATH`
- Required profile: `KC_ADMIN_MCP_TEST_GATE_REQUIRED_PROFILE`
- Enforcement mode: `KC_ADMIN_MCP_STARTUP_ADMISSION_MODE` (`off|warn|strict`)

Break-glass bypass:

- `KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS=1`
- `KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS_REASON` required
- `KC_ADMIN_MCP_STARTUP_ADMISSION_BYPASS_TTL_S` required and > 0
- Production bypass requires `KC_ADMIN_MCP_STARTUP_ADMISSION_ALLOW_PROD_BYPASS=1`

### Pass/Fail Semantics

| Condition | `off` | `warn` | `strict` |
| --- | --- | --- | --- |
| Runtime provenance unavailable | continue (`disabled`) | continue (`warning`) | fail startup (`rejected`) |
| Gate artifact missing/unreadable | continue (`disabled`) | continue (`warning`) | fail startup (`rejected`) |
| Artifact schema mismatch | continue (`disabled`) | continue (`warning`) | fail startup (`rejected`) |
| Artifact level mismatch | continue (`disabled`) | continue (`warning`) | fail startup (`rejected`) |
| `build_identity` mismatch | continue (`disabled`) | continue (`warning`) | fail startup (`rejected`) |
| `source_fingerprint` mismatch | continue (`disabled`) | continue (`warning`) | fail startup (`rejected`) |
| Bypass active with valid reason/TTL | continue (`bypassed`) | continue (`bypassed`) | continue (`bypassed`) |
| Gate artifact valid + identity match | continue (`disabled`) | continue (`passed`) | continue (`passed`) |

## Deployment Flow Touchpoints

1. Build:
- Inject `KC_ADMIN_MCP_BUILD_*` (or `MCP_BUILD_*`) values in CI/build-helper.
- Generate fast/standard gate artifacts using the fleet test-gate contract.

2. Pre-restart validation:
- Confirm gate artifact profile matches rollout level.
- Confirm artifact `build_identity` and `source_fingerprint` match target binary.

3. Startup:
- Service evaluates runtime provenance + required gate artifact.
- In strict mode, mismatches/invalid artifacts block startup.
- Admission result is logged with outcome/reason code.

4. Post-restart verification:
- Read `kc-admin://attest` and verify v2 identity fields.
- Verify admission extension indicates expected outcome/profile.
- Capture `request_id` from validation calls for audit correlation.
- If attestation access is denied, classify by auth reason bucket (`missing_token`,
  `missing_scopes`, `missing_roles`) before escalation.

## Operator Failure Buckets

When startup fails or degrades, operators should triage using these buckets:

- `admission.runtime.provenance_unavailable`
- `admission.gate.missing_or_unreadable`
- `admission.gate.schema_mismatch`
- `admission.gate.level_mismatch`
- `admission.gate.build_identity_mismatch`
- `admission.gate.source_fingerprint_mismatch`
- `admission.bypass.invalid`

These buckets are intended to be stable for alerting and runbook automation.
