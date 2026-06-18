//! # Audit Logging
//!
//! Provides a secure, tamper-evident ledger for Keycloak administrative actions.
//!
//! ## Rationale
//! Administrative actions in Keycloak are high-risk. This module ensures that every
//! tool call is recorded with its outcome, actor identity, and a cryptographic
//! hash chain to detect tampering.
//!
//! ## Security Boundaries
//! * **Hash Chain**: Each entry binds to the hash of the previous entry, preventing silent deletions.
//! * **Least Privilege**: The audit log should be written to a dedicated directory with restricted access.
//!
//! ## References
//! * **SECURITY**: `SECURITY.md`

use std::collections::VecDeque;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Identity attached to audit entries (subject/client/scopes/roles).
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug, Serialize)]
pub struct AuditActor {
    pub subject: Option<String>,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub actor_id: Option<String>,
}

/// Tool metadata recorded in each audit entry.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug, Serialize)]
pub struct AuditTool {
    pub name: String,
}

/// Outcome metadata (status/duration) stored in the audit log.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug, Serialize)]
pub struct AuditOutcome {
    pub status: String,
    pub duration_ms: u64,
}

/// Complete audit event entry written to disk/memory.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug, Serialize)]
pub struct AuditEntry {
    pub schema_version: String,
    pub event_type: String,
    pub ts: String,
    pub request_id: String,
    pub prev_hash: Option<String>,
    pub hash: Option<String>,
    pub actor: Option<AuditActor>,
    pub tool: AuditTool,
    pub outcome: AuditOutcome,
}

/// Checkpoint metadata used when rotating audit logs.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug, Serialize)]
pub struct AuditCheckpoint {
    pub schema_version: String,
    pub ts: String,
    pub last_hash: Option<String>,
    pub log_path: Option<String>,
    pub state_path: Option<String>,
    pub checkpoint_path: Option<String>,
}

/// In-memory ring buffer + optional on-disk writer for audit entries.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub struct AuditLog {
    entries: Mutex<VecDeque<AuditEntry>>,
    max_entries: usize,
    last_hash: Mutex<Option<String>>,
    log_path: Option<PathBuf>,
    checkpoint_path: Option<PathBuf>,
    log_max_bytes: Option<u64>,
    log_max_files: usize,
    file_lock: Mutex<()>,
}

impl AuditLog {
    /// Create a new audit log writer with configurable retention and files.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Caveats
    /// * None.
    pub fn new(
        max_entries: usize,
        log_path: Option<PathBuf>,
        checkpoint_path: Option<PathBuf>,
        log_max_bytes: Option<u64>,
        log_max_files: usize,
    ) -> Self {
        let max_entries = if max_entries == 0 { 1 } else { max_entries };
        Self {
            entries: Mutex::new(VecDeque::new()),
            max_entries,
            last_hash: Mutex::new(None),
            log_path,
            checkpoint_path,
            log_max_bytes,
            log_max_files,
            file_lock: Mutex::new(()),
        }
    }

    /// Append an audit entry to the ring buffer and optional file.
    ///
    /// # Security
    /// * **Tamper Evidence**: Computes a SHA-256 hash of the entry and chains it to the `prev_hash`.
    /// * **Rotation**: Automatically rotates the audit log file if it exceeds the size limit.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Caveats
    /// * None.
    pub fn record(&self, mut entry: AuditEntry) {
        let mut last_hash_guard = self.last_hash.lock().expect("audit log hash lock poisoned");
        entry.prev_hash = last_hash_guard.clone();
        entry.hash = Some(hash_entry(&entry));
        *last_hash_guard = entry.hash.clone();

        if let Some(path) = self.log_path.as_ref() {
            let _guard = self.file_lock.lock().expect("audit log file lock poisoned");
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Err(err) = rotate_if_needed(path, self.log_max_bytes, self.log_max_files) {
                tracing::warn!(error = %err, "audit log rotation failed");
            }
            if let Err(err) = append_line(path, &entry) {
                tracing::warn!(error = %err, "audit log write failed");
            }
        }

        let mut entries = self
            .entries
            .lock()
            .expect("audit log entries lock poisoned");
        entries.push_back(entry);
        while entries.len() > self.max_entries {
            entries.pop_front();
        }
    }

    /// Return the most recent audit entries (at most `limit`) in chronological order.
    ///
    /// # Errors
    /// * Does not return errors.
    ///
    /// # Security
    /// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
    ///
    /// # Caveats
    /// * None.
    pub fn snapshot(&self, limit: usize) -> Vec<AuditEntry> {
        let limit = if limit == 0 { 1 } else { limit };
        let entries = self
            .entries
            .lock()
            .expect("audit log entries lock poisoned");
        entries
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    /// Flush audit log state to disk and return a checkpoint hash bundle.
    ///
    /// # Security
    /// * **Persistence**: Ensures that the current hash chain state is committed to a checkpoint file.
    ///
    /// # Errors
    /// * Returns an error if the operation fails.
    ///
    /// # Caveats
    /// * None.
    pub fn checkpoint(&self) -> Result<AuditCheckpoint, std::io::Error> {
        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string());
        let last_hash = self
            .last_hash
            .lock()
            .expect("audit log hash lock poisoned")
            .clone();

        let log_path = self.log_path.clone();
        if let Some(path) = log_path.as_ref() {
            let entries = self.snapshot(self.max_entries);
            let mut contents = String::new();
            for entry in entries {
                let line = serde_json::to_string(&entry).unwrap_or_else(|_| "{}".to_string());
                contents.push_str(&line);
                contents.push('\n');
            }
            fs::write(path, contents)?;
        }

        let checkpoint = AuditCheckpoint {
            schema_version: "v1".to_string(),
            ts,
            last_hash,
            log_path: log_path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string()),
            state_path: self
                .checkpoint_path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string()),
            checkpoint_path: self
                .checkpoint_path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string()),
        };

        if let Some(path) = self.checkpoint_path.as_ref() {
            let payload =
                serde_json::to_string_pretty(&checkpoint).unwrap_or_else(|_| "{}".to_string());
            fs::write(path, payload)?;
        }

        Ok(checkpoint)
    }
}

fn hash_entry(entry: &AuditEntry) -> String {
    let mut clone = entry.clone();
    clone.hash = None;
    let payload = serde_json::to_vec(&clone).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

fn append_line(path: &PathBuf, entry: &AuditEntry) -> Result<(), std::io::Error> {
    let line = serde_json::to_string(entry).unwrap_or_else(|_| "{}".to_string());
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn rotate_if_needed(
    path: &PathBuf,
    max_bytes: Option<u64>,
    max_files: usize,
) -> Result<(), std::io::Error> {
    let Some(max_bytes) = max_bytes else {
        return Ok(());
    };
    if max_bytes == 0 || max_files == 0 {
        return Ok(());
    }

    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    if metadata.len() < max_bytes {
        return Ok(());
    }

    for idx in (1..=max_files).rev() {
        let rotated = rotated_path(path, idx);
        if idx == max_files && rotated.exists() {
            let _ = fs::remove_file(&rotated);
        }
        let previous = if idx == 1 {
            path.clone()
        } else {
            rotated_path(path, idx - 1)
        };
        if previous.exists() {
            let _ = fs::rename(previous, rotated);
        }
    }

    Ok(())
}

fn rotated_path(path: &PathBuf, idx: usize) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.display(), idx))
}
