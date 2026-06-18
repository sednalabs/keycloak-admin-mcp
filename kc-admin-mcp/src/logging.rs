//! # MCP Logging
//!
//! Configures structured tracing and multi-stream log routing for the MCP server.
//!
//! ## Rationale
//! Separates operational logs, access logs, and security logs into distinct streams
//! to support both real-time monitoring and long-term auditing.
//!
//! ## Security Boundaries
//! * **Audit Separation**: Security-sensitive events are routed to a dedicated auth log.
//! * **Context Enrichment**: Injects `request_id` and `actor` into every log line.

use std::path::PathBuf;

use tracing_subscriber::filter::{EnvFilter, LevelFilter, Targets};
use tracing_subscriber::fmt as fmt_subscriber;
use tracing_subscriber::prelude::*;

use mcp_toolkit_observability::logging::{
    ContextMap, LogFormat, LogFormatter, LogTargets, RoutingWriter,
};

use crate::log_context;

const LOG_LEVEL_ENV: &str = "KC_ADMIN_MCP_LOG_LEVEL";
const LOG_FORMAT_ENV: &str = "KC_ADMIN_MCP_LOG_FORMAT";
const LOG_FILE_ENV: &str = "KC_ADMIN_MCP_LOG_FILE";
const LOG_ACCESS_FILE_ENV: &str = "KC_ADMIN_MCP_ACCESS_LOG_FILE";
const LOG_AUTH_FILE_ENV: &str = "KC_ADMIN_MCP_AUTH_LOG_FILE";

/// Target used for access log events.
pub const LOG_TARGET_ACCESS: &str = "kc_admin_mcp.access";
/// Target used for authentication log events.
pub const LOG_TARGET_AUTH: &str = "kc_admin_mcp.auth";

/// Configure tracing/subscriber logging according to env variables.
///
/// # Errors
/// * Does not return errors.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn configure_logging() {
    let format = LogFormat::from_env(LOG_FORMAT_ENV, LogFormat::Logfmt);
    let filter = match std::env::var(LOG_LEVEL_ENV) {
        Ok(level) => EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info")),
        Err(_) => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    };

    let writer = RoutingWriter::new(
        env_path(LOG_FILE_ENV),
        env_path(LOG_ACCESS_FILE_ENV),
        env_path(LOG_AUTH_FILE_ENV),
        LogTargets::new(LOG_TARGET_ACCESS, LOG_TARGET_AUTH),
    );
    let formatter = LogFormatter::new(format, context_map);
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

fn context_map() -> ContextMap {
    let mut map = ContextMap::new();
    if let Some(context) = log_context::current() {
        if let Some(request_id) = context.request_id {
            map.insert("request_id".to_string(), request_id);
        }
        if let Some(actor) = context.actor_id {
            map.insert("actor".to_string(), actor);
        }
        if let Some(session_id) = context.session_id {
            map.insert("session_id".to_string(), session_id);
        }
        if let Some(method) = context.method {
            map.insert("method".to_string(), method);
        }
        if let Some(path) = context.path {
            map.insert("path".to_string(), path);
        }
        if let Some(tool) = context.tool {
            map.insert("tool".to_string(), tool);
        }
    }
    map
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}
