//! # Runtime Provenance + Fleet Attestation Envelope
//!
//! Captures deterministic build/source identity and emits a fleet-aligned v2
//! attestation payload for operators.
//!
//! ## Rationale
//! Startup and incident triage require a stable mapping from a running process
//! to its source/build lineage.
//!
//! ## Security Boundaries
//! * Reads only local executable metadata.
//! * Exposes non-secret build/runtime metadata fields.
//!
//! ## References
//! * `docs/provenance-test-gate-design.md`
//! * `docs/RUNBOOK.md`

use serde::Serialize;
use serde_json::{json, Value};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const UNKNOWN: &str = "unknown";

#[derive(Debug, Clone, Serialize)]
pub struct BuildProvenance {
    pub component: String,
    pub server_version: String,
    pub build_identity: String,
    pub source_fingerprint: String,
    pub source: SourceProvenance,
    pub build_metadata: BuildMetadata,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceProvenance {
    pub vcs: String,
    pub revision: String,
    pub reference: String,
    pub dirty: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildMetadata {
    pub profile: String,
    pub target: String,
    pub rustc_version: String,
    pub source_date_epoch: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessProvenance {
    pub pid: u32,
    pub executable_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryProvenance {
    pub file_size_bytes: Option<u64>,
    pub modified_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeProvenance {
    pub build: BuildProvenance,
    pub process: ProcessProvenance,
    pub binary: BinaryProvenance,
}

#[derive(Debug, Clone)]
pub struct RuntimeProvenanceSnapshot {
    pub executable_path: PathBuf,
    pub provenance: RuntimeProvenance,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeAdmissionExtension {
    pub enforcement_phase: String,
    pub required_gate_level: String,
    pub outcome: String,
    pub reason_code: Option<String>,
    pub override_active: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnavailableField {
    pub field: String,
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttestationIdentity {
    pub server_version: String,
    pub contract_version: Option<String>,
    pub build_identity: String,
    pub source_fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttestationRuntime {
    pub pid: Option<u32>,
    pub executable_path: Option<String>,
    pub binary_size_bytes: Option<u64>,
    pub binary_modified_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttestationPayload {
    pub identity: AttestationIdentity,
    pub source: SourceProvenance,
    pub build_metadata: BuildMetadata,
    pub runtime: AttestationRuntime,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttestationEnvelope {
    pub status: String,
    pub schema_version: u32,
    pub component: String,
    pub timestamp: String,
    pub request_id: Option<String>,
    pub attestation: AttestationPayload,
    pub unavailable: Vec<UnavailableField>,
    pub extensions: Value,
}

static BUILD_PROVENANCE: OnceLock<BuildProvenance> = OnceLock::new();

/// Return cached compile-time provenance values for this build.
pub fn build_provenance() -> &'static BuildProvenance {
    BUILD_PROVENANCE.get_or_init(BuildProvenance::from_build_env)
}

/// Captures process and binary metadata for the current executable.
///
/// # Errors
/// Returns an I/O error when the operating system cannot resolve the current
/// executable path.
///
/// # Security
/// The executable path is resolved from `std::env::current_exe()` inside this
/// function. Production callers cannot supply arbitrary filesystem paths, and
/// the attestation intentionally avoids filesystem metadata reads from that
/// path.
pub fn capture_runtime_provenance() -> std::io::Result<RuntimeProvenanceSnapshot> {
    let executable_path = std::env::current_exe()?;
    let provenance = RuntimeProvenance {
        build: build_provenance().clone(),
        process: ProcessProvenance {
            pid: std::process::id(),
            executable_path: executable_path.display().to_string(),
        },
        binary: BinaryProvenance {
            file_size_bytes: None,
            modified_unix_ms: None,
        },
    };
    Ok(RuntimeProvenanceSnapshot {
        executable_path,
        provenance,
    })
}

#[cfg(test)]
pub(crate) fn capture_runtime_provenance_for_test(executable_path: &Path) -> RuntimeProvenance {
    RuntimeProvenance {
        build: build_provenance().clone(),
        process: ProcessProvenance {
            pid: std::process::id(),
            executable_path: executable_path.display().to_string(),
        },
        binary: BinaryProvenance {
            file_size_bytes: None,
            modified_unix_ms: None,
        },
    }
}

/// Build the fleet attestation envelope (schema v2) from runtime provenance.
pub fn build_attestation_envelope(
    provenance: &RuntimeProvenance,
    admission: &RuntimeAdmissionExtension,
) -> AttestationEnvelope {
    let mut unavailable = Vec::new();
    if provenance.build.source.revision == UNKNOWN {
        unavailable.push(UnavailableField {
            field: "attestation.source.revision".to_string(),
            code: "provenance.unavailable.git_revision".to_string(),
            reason: "git revision unavailable in build context".to_string(),
        });
    }
    if provenance.build.source.reference == UNKNOWN {
        unavailable.push(UnavailableField {
            field: "attestation.source.reference".to_string(),
            code: "provenance.unavailable.git_reference".to_string(),
            reason: "git reference unavailable in build context".to_string(),
        });
    }
    if provenance.build.build_metadata.rustc_version == UNKNOWN {
        unavailable.push(UnavailableField {
            field: "attestation.build_metadata.rustc_version".to_string(),
            code: "provenance.unavailable.rustc_version".to_string(),
            reason: "rustc version unavailable in build context".to_string(),
        });
    }

    let admission_degraded = matches!(admission.outcome.as_str(), "warn" | "bypassed" | "disabled");
    let status = if unavailable.is_empty() && !admission_degraded {
        "ok".to_string()
    } else {
        "degraded".to_string()
    };

    AttestationEnvelope {
        status,
        schema_version: 2,
        component: provenance.build.component.clone(),
        timestamp: now_rfc3339(),
        request_id: None,
        attestation: AttestationPayload {
            identity: AttestationIdentity {
                server_version: provenance.build.server_version.clone(),
                contract_version: None,
                build_identity: provenance.build.build_identity.clone(),
                source_fingerprint: provenance.build.source_fingerprint.clone(),
            },
            source: provenance.build.source.clone(),
            build_metadata: provenance.build.build_metadata.clone(),
            runtime: AttestationRuntime {
                pid: Some(provenance.process.pid),
                executable_path: Some(provenance.process.executable_path.clone()),
                binary_size_bytes: provenance.binary.file_size_bytes,
                binary_modified_unix_ms: provenance.binary.modified_unix_ms,
            },
        },
        unavailable,
        extensions: json!({
            "runtime_admission": admission,
        }),
    }
}

impl BuildProvenance {
    fn from_build_env() -> Self {
        let component = build_env("KC_ADMIN_MCP_BUILD_COMPONENT")
            .or_else(|| Some(env!("CARGO_PKG_NAME").to_string()))
            .unwrap_or_else(|| env!("CARGO_PKG_NAME").to_string());
        let server_version = build_env("KC_ADMIN_MCP_BUILD_SERVER_VERSION")
            .or_else(|| Some(env!("CARGO_PKG_VERSION").to_string()))
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
        let revision =
            build_env("KC_ADMIN_MCP_BUILD_GIT_SHA").unwrap_or_else(|| UNKNOWN.to_string());
        let reference =
            build_env("KC_ADMIN_MCP_BUILD_GIT_REF").unwrap_or_else(|| UNKNOWN.to_string());
        let dirty = parse_truthy(option_env!("KC_ADMIN_MCP_BUILD_GIT_DIRTY"));
        let identity_override = build_env("KC_ADMIN_MCP_BUILD_IDENTITY_OVERRIDE");
        let source_fingerprint = source_fingerprint(&revision, dirty);
        let build_identity = identity_override
            .unwrap_or_else(|| build_identity(&component, &server_version, &revision, dirty));
        let build_metadata = BuildMetadata {
            profile: build_env("KC_ADMIN_MCP_BUILD_PROFILE").unwrap_or_else(|| UNKNOWN.to_string()),
            target: build_env("KC_ADMIN_MCP_BUILD_TARGET").unwrap_or_else(|| UNKNOWN.to_string()),
            rustc_version: build_env("KC_ADMIN_MCP_BUILD_RUSTC_VERSION")
                .unwrap_or_else(|| UNKNOWN.to_string()),
            source_date_epoch: build_env("KC_ADMIN_MCP_BUILD_SOURCE_DATE_EPOCH"),
        };

        Self {
            component,
            server_version,
            build_identity,
            source_fingerprint,
            source: SourceProvenance {
                vcs: "git".to_string(),
                revision,
                reference,
                dirty,
            },
            build_metadata,
        }
    }
}

fn build_env(key: &str) -> Option<String> {
    let value = option_env_any([key])?;
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == UNKNOWN {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn option_env_any<const N: usize>(keys: [&str; N]) -> Option<&'static str> {
    for key in keys {
        if let Some(value) = option_env_for(key) {
            return Some(value);
        }
    }
    None
}

fn option_env_for(key: &str) -> Option<&'static str> {
    match key {
        "KC_ADMIN_MCP_BUILD_COMPONENT" => option_env!("KC_ADMIN_MCP_BUILD_COMPONENT"),
        "KC_ADMIN_MCP_BUILD_SERVER_VERSION" => option_env!("KC_ADMIN_MCP_BUILD_SERVER_VERSION"),
        "KC_ADMIN_MCP_BUILD_GIT_SHA" => option_env!("KC_ADMIN_MCP_BUILD_GIT_SHA"),
        "KC_ADMIN_MCP_BUILD_GIT_REF" => option_env!("KC_ADMIN_MCP_BUILD_GIT_REF"),
        "KC_ADMIN_MCP_BUILD_GIT_DIRTY" => option_env!("KC_ADMIN_MCP_BUILD_GIT_DIRTY"),
        "KC_ADMIN_MCP_BUILD_PROFILE" => option_env!("KC_ADMIN_MCP_BUILD_PROFILE"),
        "KC_ADMIN_MCP_BUILD_TARGET" => option_env!("KC_ADMIN_MCP_BUILD_TARGET"),
        "KC_ADMIN_MCP_BUILD_RUSTC_VERSION" => option_env!("KC_ADMIN_MCP_BUILD_RUSTC_VERSION"),
        "KC_ADMIN_MCP_BUILD_SOURCE_DATE_EPOCH" => {
            option_env!("KC_ADMIN_MCP_BUILD_SOURCE_DATE_EPOCH")
        }
        "KC_ADMIN_MCP_BUILD_IDENTITY_OVERRIDE" => {
            option_env!("KC_ADMIN_MCP_BUILD_IDENTITY_OVERRIDE")
        }
        _ => None,
    }
}

fn parse_truthy(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

fn source_fingerprint(revision: &str, dirty: bool) -> String {
    let cleanliness = if dirty { "dirty" } else { "clean" };
    format!("git:{revision}:{cleanliness}")
}

fn build_identity(component: &str, server_version: &str, revision: &str, dirty: bool) -> String {
    let mut value = format!("{component}@{server_version}+{revision}");
    if dirty {
        value.push_str("-dirty");
    }
    value
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::{build_identity, parse_truthy, source_fingerprint};

    #[test]
    fn source_fingerprint_marks_clean_and_dirty() {
        assert_eq!(source_fingerprint("abc123", false), "git:abc123:clean");
        assert_eq!(source_fingerprint("abc123", true), "git:abc123:dirty");
    }

    #[test]
    fn build_identity_appends_dirty_suffix_only_when_needed() {
        assert_eq!(
            build_identity("kc-admin-mcp", "0.1.0", "abc123", false),
            "kc-admin-mcp@0.1.0+abc123"
        );
        assert_eq!(
            build_identity("kc-admin-mcp", "0.1.0", "abc123", true),
            "kc-admin-mcp@0.1.0+abc123-dirty"
        );
    }

    #[test]
    fn parse_truthy_accepts_common_spellings() {
        assert!(parse_truthy(Some("1")));
        assert!(parse_truthy(Some("true")));
        assert!(parse_truthy(Some("YES")));
        assert!(parse_truthy(Some("on")));
        assert!(!parse_truthy(Some("false")));
        assert!(!parse_truthy(None));
    }
}
