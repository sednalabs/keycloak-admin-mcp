# Public Release Readiness

This repository is a hardened release candidate for `keycloak-admin-mcp`.
It is intended to be published as a clean initial public commit only after every
gate below has current evidence for the exact commit being released.

## Current Gates

| Gate | Evidence | Status |
| --- | --- | --- |
| License | The workspace includes the Apache-2.0 license text and both crates declare `license = "Apache-2.0"`. | Ready |
| Public toolkit pins | Toolkit crates are pinned to the current public `sednalabs/mcp-toolkit-rs` release-readiness commit in the workspace manifest and lockfile. | Ready |
| Publication hygiene | `scripts/release_hygiene_check.sh` and the `release-hygiene` workflow block local path dependencies, credential-shaped tracked file paths, privileged workflow patterns, and lockfile drift. | Ready pending hosted run |
| Dependency governance | `dependency-governance` runs `cargo-deny`, `cargo-audit`, and direct-dependency stale-risk checks with pinned workflow actions. | Ready pending hosted run |
| Code scanning | The pinned Rust CodeQL workflow uploads SARIF automatically when the release commit runs in a public repository. | Ready pending public `main` run |
| Secret scanning | Final release requires GitHub secret scanning to be enabled on the public repository and report zero open alerts for the release commit. | Ready pending public repository |
| Final publication approval | Public repository creation for a clean initial commit is approved for this release candidate. Registry publication and compatibility claims remain out of scope. | Ready |

## Before Public Release

1. Land the release-readiness updates and verify a clean candidate tree.
2. Create `sednalabs/keycloak-admin-mcp` as a public repository from a clean
   initial commit, not by exposing private history.
3. Verify successful `release-hygiene`, `dependency-governance`, and upload-enabled
   CodeQL runs on public `main`.
4. Enable and confirm Dependabot, code-scanning, and secret-scanning alert counts.
5. Record the audited commit, workflow run IDs, alert counts, and any accepted
   residual risks before making a public reference-release claim.
