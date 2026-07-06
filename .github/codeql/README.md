# CodeQL and SARIF posture

This repository uses workflow-based CodeQL advanced setup rather than default
setup.

## CodeQL analyses

- Rust analysis runs with the `security-and-quality` suite and the local threat
  model enabled.
- GitHub Actions analysis runs with the `security-and-quality` suite plus the
  repository's bespoke `sednalabs/actions-workflow-security` query pack.
- The bespoke pack checks workflow-specific release, token, logging, provenance,
  and SARIF upload invariants for this repository.

## SARIF uploads

The public code-scanning surface receives multiple SARIF streams:

- CodeQL Rust analysis.
- CodeQL GitHub Actions analysis, including bespoke workflow-security queries.
- DevSkim static-analysis SARIF.
- OSV dependency vulnerability SARIF.
- Trivy filesystem SARIF for vulnerability, misconfiguration, secret, and
  license findings.

Every direct `github/codeql-action/upload-sarif` step should set a stable
`category` input so GitHub code scanning keeps multi-tool analyses distinct.
