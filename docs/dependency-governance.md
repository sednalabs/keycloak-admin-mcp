# Dependency Governance

This document defines dependency selection and upgrade policy for this repository's Rust components.

## Goal

Keep Rust components secure, maintainable, and release-friendly by preferring well-maintained crates with clear operational risk signals.

## Scope

- Direct dependencies declared in Cargo manifests for the governed Rust workspaces
- Tooling dependencies used in release checks
- New crates and major/minor dependency upgrades

## Go/No-Go Criteria

All new direct crates and major upgrades must meet every hard gate below.

1. `security`: No unresolved RustSec advisory for selected version.
2. `license`: License is allowlisted by `deny.toml`.
3. `source`: Registry source is trusted. Direct registry dependencies must come
   from `crates.io`; unpublished toolkit crates may come from the public
   `https://github.com/sednalabs/mcp-toolkit-rs` repository when pinned to an
   exact revision in the workspace manifest.
4. `maintenance`: Evidence of active maintenance (recent releases, active issue/PR activity, non-abandoned project).
5. `adoption/reputation`: Evidence the crate is broadly used or maintained by a trusted team/project.
6. `fit`: Clear justification that existing dependencies or stdlib cannot solve the need with lower risk.

If any hard gate fails, the change is `no-go` unless an explicit, time-bounded exception is approved and documented.

## Required Evidence for Dependency Changes

Every dependency change (new crate, removed crate, major/minor upgrade) must include a policy note in the associated PR description.

Use this template:

```text
Dependency change note
- crate: <name> <old -> new>
- change type: <new | upgrade | removal>
- purpose: <why needed>
- alternatives considered: <stdlib/existing crates/other crates>
- maintenance evidence: <release recency + repo activity>
- adoption/reputation evidence: <reverse-deps/downloads/known users or maintainer org>
- security status: <cargo deny + cargo audit result>
- license status: <allowlisted license(s)>
- startup impact: <expected effect on cold start/steady state>
- rollback plan: <how to revert safely>
- exception (if any): <risk accepted, owner, expiry date>
```

## Enforcement

Run:

```bash
./scripts/dependency_governance_check.sh
```

The script enforces:

1. advisory/license/source policy via `cargo-deny` (blocking)
2. RustSec check via `cargo-audit` (blocking)
3. stale-risk scan on direct dependencies via `cargo-outdated` (report-only by default)

The stale-risk scan skips direct dependencies that must stay aligned with
toolkit exact-version pins. Advisory, audit, license, and source checks remain
blocking for those dependencies.

The current toolkit dependency exception is intentionally narrow: the MCP
Toolkit crates are consumed from the public `sednalabs/mcp-toolkit-rs`
repository at a fixed revision until the selected crates are published to a
registry. Do not reintroduce sibling checkout paths for release candidates.

Phase-2 tightening option:

```bash
STRICT_OUTDATED=1 ./scripts/dependency_governance_check.sh
```

When `STRICT_OUTDATED=1`, outdated direct dependencies become a failing gate.

## Exceptions

Exceptions are allowed only when there is a clear delivery blocker and no safer near-term option.

Exception requirements:

1. Documented in PR with rationale, owner, and explicit expiry date.
2. Bounded duration (target <= 30 days).
3. Follow-up issue/work item created before merge.
