//! # Log Sanitization
//!
//! Utilities for scrubbing sensitive data from logs.
//!
//! ## Rationale
//! Prevents accidental leakage of secrets (tokens, client IDs) and PII into structured logs.
//! All dynamic values in log messages must pass through these filters.
//!
//! ## Security Boundaries
//! * **Secret Redaction**: Detects and masks patterns that resemble credentials.
//! * **Denial of Service**: Truncates long values to prevent log flooding.

use mcp_toolkit_observability::sanitize::{
    sanitize_exchange_error as toolkit_exchange_error,
    sanitize_log_value_with_limit as toolkit_log_value_with_limit,
};

const MAX_LOG_VALUE: usize = 128;

/// Sanitize arbitrary log values (redact secrets/truncate).
///
/// # Security
/// * **Redaction**: Replaces sensitive data with `[REDACTED]`.
///
/// # Errors
/// * Does not return errors.
///
/// # Caveats
/// * None.
pub fn sanitize_log_value(value: &str) -> String {
    sanitize_log_value_with_limit(value, MAX_LOG_VALUE)
}

/// Sanitize log values with a configurable length limit.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn sanitize_log_value_with_limit(value: &str, max_len: usize) -> String {
    toolkit_log_value_with_limit(value, max_len)
}

/// Sanitize token exchange error bodies before writing to structured logs.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn sanitize_exchange_error(raw: &str, max_bytes: usize) -> String {
    toolkit_exchange_error(raw, max_bytes)
}
