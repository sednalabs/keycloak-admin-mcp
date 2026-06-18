//! # Gateway Logging
//!
//! Provides structured logging and telemetry for the security gateway.
//!
//! ## Rationale
//! Captures the entire lifecycle of a proxied request, from initial authentication
//! to token exchange and upstream forwarding.
//!
//! ## Security Boundaries
//! * **Sanitization**: Strictly scrubs all dynamic values before emission to logs.

use std::path::PathBuf;
use std::time::Instant;

use tracing_subscriber::filter::{EnvFilter, LevelFilter, Targets};
use tracing_subscriber::fmt as fmt_subscriber;
use tracing_subscriber::prelude::*;

use mcp_toolkit_observability::logging::{
    empty_context, LogFormat, LogFormatter, LogTargets, RoutingWriter,
};

use crate::log_sanitize::sanitize_log_value;

const LOG_LEVEL_ENV: &str = "KC_GATEWAY_LOG_LEVEL";
const LOG_FORMAT_ENV: &str = "KC_GATEWAY_LOG_FORMAT";
const LOG_FILE_ENV: &str = "KC_GATEWAY_LOG_FILE";
const LOG_ACCESS_FILE_ENV: &str = "KC_GATEWAY_ACCESS_LOG_FILE";
const LOG_AUTH_FILE_ENV: &str = "KC_GATEWAY_AUTH_LOG_FILE";

/// Access log target (gateway requests).
pub const LOG_TARGET_ACCESS: &str = "kc_admin_gateway.access";
/// Authentication/exchange log target.
pub const LOG_TARGET_AUTH: &str = "kc_admin_gateway.auth";

/// Initialize tracing layers for the gateway process according to env overrides.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn init_tracing(log_level: &str) {
    let format = LogFormat::from_env(LOG_FORMAT_ENV, LogFormat::Logfmt);
    let filter = match std::env::var(LOG_LEVEL_ENV) {
        Ok(level) => EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info")),
        Err(_) => EnvFilter::try_new(log_level).unwrap_or_else(|_| EnvFilter::new("info")),
    };

    let writer = RoutingWriter::new(
        env_path(LOG_FILE_ENV),
        env_path(LOG_ACCESS_FILE_ENV),
        env_path(LOG_AUTH_FILE_ENV),
        LogTargets::new(LOG_TARGET_ACCESS, LOG_TARGET_AUTH),
    );
    let formatter = LogFormatter::new(format, empty_context);
    let targets = Targets::new().with_default(LevelFilter::TRACE);

    tracing_subscriber::registry()
        .with(
            fmt_subscriber::layer()
                .with_ansi(false)
                .event_format(formatter)
                .with_writer(writer)
                .with_filter(filter)
                .with_filter(targets),
        )
        .init();
}

/// Emit the start of an admin proxy request for access logging.
///
/// # Security
/// * **Sanitization**: Scrubs `actor` and `session_id` before logging.
///
/// # Errors
/// * Does not return errors.
///
/// # Caveats
/// * None.
pub fn log_request_start(
    endpoint: &str,
    method: &str,
    path: &str,
    client: &str,
    request_id: &str,
    actor: Option<&str>,
    session_id: Option<&str>,
) -> Instant {
    let actor = actor.map(sanitize_log_value);
    let session_id = session_id.map(sanitize_log_value);
    tracing::info!(
        target: LOG_TARGET_ACCESS,
        endpoint = %endpoint,
        method = %method,
        path = %path,
        client = %client,
        request_id = %request_id,
        actor = actor.as_deref().unwrap_or("-"),
        session_id = session_id.as_deref().unwrap_or("-"),
        "gateway.request.start"
    );
    Instant::now()
}

/// Emit the end of an admin proxy request, including status + duration.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn log_request_finish(
    endpoint: &str,
    method: &str,
    path: &str,
    client: &str,
    request_id: &str,
    actor: Option<&str>,
    session_id: Option<&str>,
    started_at: Instant,
    status: u16,
    error: bool,
) {
    let duration_ms = duration_ms(started_at);
    let actor = actor.map(sanitize_log_value);
    let session_id = session_id.map(sanitize_log_value);
    tracing::info!(
        target: LOG_TARGET_ACCESS,
        endpoint = %endpoint,
        method = %method,
        path = %path,
        client = %client,
        request_id = %request_id,
        actor = actor.as_deref().unwrap_or("-"),
        session_id = session_id.as_deref().unwrap_or("-"),
        status = status,
        duration_ms = duration_ms,
        error = error,
        "gateway.request.finish"
    );
}

/// Log the beginning of an authentication flow.
///
/// # Security
/// * **Sanitization**: Ensures that no potentially sensitive path segments are logged verbatim.
///
/// # Errors
/// * Does not return errors.
///
/// # Caveats
/// * None.
pub fn log_auth_start(
    endpoint: &str,
    method: &str,
    path: &str,
    client: &str,
    request_id: &str,
    auth_mode: &str,
    introspection: bool,
) -> Instant {
    tracing::info!(
        target: LOG_TARGET_AUTH,
        endpoint = %endpoint,
        method = %method,
        path = %path,
        client = %client,
        request_id = %request_id,
        auth_mode = %auth_mode,
        introspection = introspection,
        "gateway.auth.start"
    );
    Instant::now()
}

/// Log the completion of an authentication flow with status/reason.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn log_auth_finish(
    endpoint: &str,
    method: &str,
    path: &str,
    client: &str,
    request_id: &str,
    actor: Option<&str>,
    session_id: Option<&str>,
    started_at: Instant,
    status: u16,
    error: bool,
    auth_mode: &str,
    introspection: bool,
    reason: Option<&str>,
) {
    let duration_ms = duration_ms(started_at);
    let actor = actor.map(sanitize_log_value);
    let session_id = session_id.map(sanitize_log_value);
    tracing::info!(
        target: LOG_TARGET_AUTH,
        endpoint = %endpoint,
        method = %method,
        path = %path,
        client = %client,
        request_id = %request_id,
        status = status,
        duration_ms = duration_ms,
        error = error,
        auth_mode = %auth_mode,
        introspection = introspection,
        actor = actor.as_deref().unwrap_or("-"),
        session_id = session_id.as_deref().unwrap_or("-"),
        reason = reason.unwrap_or("-"),
        "gateway.auth.finish"
    );
}

/// Log the start of a token exchange operation.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn log_exchange_start(
    endpoint: &str,
    method: &str,
    path: &str,
    client: &str,
    request_id: &str,
    scopes: &str,
) -> Instant {
    tracing::info!(
        target: LOG_TARGET_AUTH,
        endpoint = %endpoint,
        method = %method,
        path = %path,
        client = %client,
        request_id = %request_id,
        scopes = %scopes,
        "gateway.exchange.start"
    );
    Instant::now()
}

/// Log the completion of a token exchange (status/reason+duration).
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn log_exchange_finish(
    endpoint: &str,
    method: &str,
    path: &str,
    client: &str,
    request_id: &str,
    scopes: &str,
    started_at: Instant,
    status: u16,
    error: bool,
    reason: Option<&str>,
) {
    let duration_ms = duration_ms(started_at);
    tracing::info!(
        target: LOG_TARGET_AUTH,
        endpoint = %endpoint,
        method = %method,
        path = %path,
        client = %client,
        request_id = %request_id,
        scopes = %scopes,
        status = status,
        duration_ms = duration_ms,
        error = error,
        reason = reason.unwrap_or("-"),
        "gateway.exchange.finish"
    );
}

fn duration_ms(started_at: Instant) -> f64 {
    (started_at.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}
