//! # Shared Tool Helpers
//!
//! Common utilities for authentication extraction and authorization gating.
//!
//! ## Rationale
//! Provides a centralized way to enforce scope and role requirements across all tools.
//! It ensures that the logic for classifying "Read" vs "Write" actions remains consistent
//! throughout the codebase.
//!
//! ## Security Boundaries
//! * **Scope Enforcement**: Final check before any tool call reaches the gateway.
//! * **Role-Based Gating**: Maps token roles to administrative access levels.

use axum::http::request::Parts;

use crate::auth::AuthContext;
use crate::config::{Config, ScopeMap};
use crate::errors::{tool_error, tool_error_with_hint};
use rmcp::model::CallToolResult;

/// Extract the authenticated context saved in the request extensions by `auth_guard`.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn auth_from_parts(parts: &Parts) -> Result<AuthContext, CallToolResult> {
    parts
        .extensions
        .get::<AuthContext>()
        .cloned()
        .ok_or_else(|| tool_error("auth.missing_context", "Missing auth context.", "unknown"))
}

/// Ensure the token carries all required scopes; returns a structured tool error otherwise.
///
/// # Security
/// * **Fail-Closed**: Immediately returns an error if any required scope is missing.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Caveats
/// * None.
pub fn require_scopes(ctx: &AuthContext, required: &[String]) -> Result<(), CallToolResult> {
    if required.is_empty() {
        return Ok(());
    }
    let scope_set: std::collections::HashSet<&str> =
        ctx.scopes.iter().map(|s| s.as_str()).collect();
    let missing: Vec<String> = required
        .iter()
        .filter(|scope| !scope_set.contains(scope.as_str()))
        .cloned()
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(tool_error_with_hint(
        "auth.missing_scopes",
        &format!("Token missing required scopes: {}", missing.join(", ")),
        &ctx.request_id,
        "Request a token with the required scopes.",
    ))
}

/// Ensure the caller’s roles satisfy read vs write gates derived from the requested scopes.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
pub fn require_roles_for_scopes(
    ctx: &AuthContext,
    required_scopes: &[String],
    config: &Config,
) -> Result<(), CallToolResult> {
    let gate = classify_scopes(required_scopes, &config.scope_map);
    if gate == RoleGateKind::None {
        return Ok(());
    }
    let read_roles = &config.role_requirements.read;
    let write_roles = &config.role_requirements.write;
    if read_roles.is_empty() && write_roles.is_empty() {
        return Ok(());
    }

    let role_set: std::collections::HashSet<&str> = ctx.roles.iter().map(|r| r.as_str()).collect();
    if gate == RoleGateKind::Write {
        if has_any_role(&role_set, write_roles) {
            return Ok(());
        }
        return Err(tool_error_with_hint(
            "auth.missing_roles",
            &format!(
                "Token missing required roles for write access: {}",
                write_roles.join(", ")
            ),
            &ctx.request_id,
            "Assign a write role to access this tool.",
        ));
    }

    let accepted: Vec<String> = read_roles
        .iter()
        .chain(write_roles.iter())
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if has_any_role(&role_set, &accepted) {
        return Ok(());
    }

    Err(tool_error_with_hint(
        "auth.missing_roles",
        &format!(
            "Token missing required roles for read access: {}",
            read_roles.join(", ")
        ),
        &ctx.request_id,
        "Assign a read or write role to access this tool.",
    ))
}

/// Reject secret-bearing tools if the deployment disabled them via config.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[allow(dead_code)]
pub fn ensure_secret_tools_enabled(
    ctx: &AuthContext,
    config: &Config,
) -> Result<(), CallToolResult> {
    if config.enable_secret_tools {
        return Ok(());
    }
    Err(tool_error_with_hint(
        "auth.secrets_disabled",
        "Secret tools are disabled for this deployment.",
        &ctx.request_id,
        "Enable KC_ADMIN_MCP_ENABLE_SECRET_TOOLS to use secret tools.",
    ))
}

#[derive(Debug, PartialEq, Eq)]
enum RoleGateKind {
    Read,
    Write,
    None,
}

fn classify_scopes(required_scopes: &[String], scope_map: &ScopeMap) -> RoleGateKind {
    let mut write_scopes = std::collections::HashSet::new();
    write_scopes.extend(scope_map.users.write.iter().map(|s| s.as_str()));
    write_scopes.extend(scope_map.groups.write.iter().map(|s| s.as_str()));
    write_scopes.extend(scope_map.roles.write.iter().map(|s| s.as_str()));
    write_scopes.extend(scope_map.clients.write.iter().map(|s| s.as_str()));
    write_scopes.extend(scope_map.clients.secrets.iter().map(|s| s.as_str()));
    write_scopes.extend(scope_map.client_scopes.write.iter().map(|s| s.as_str()));
    write_scopes.extend(
        scope_map
            .identity_providers
            .write
            .iter()
            .map(|s| s.as_str()),
    );
    write_scopes.extend(scope_map.realms.write.iter().map(|s| s.as_str()));
    write_scopes.extend(scope_map.realms.admin.iter().map(|s| s.as_str()));
    write_scopes.extend(scope_map.events.admin.iter().map(|s| s.as_str()));

    if required_scopes
        .iter()
        .any(|scope| write_scopes.contains(scope.as_str()))
    {
        return RoleGateKind::Write;
    }

    let mut read_scopes = std::collections::HashSet::new();
    read_scopes.extend(scope_map.users.read.iter().map(|s| s.as_str()));
    read_scopes.extend(scope_map.groups.read.iter().map(|s| s.as_str()));
    read_scopes.extend(scope_map.roles.read.iter().map(|s| s.as_str()));
    read_scopes.extend(scope_map.clients.read.iter().map(|s| s.as_str()));
    read_scopes.extend(scope_map.client_scopes.read.iter().map(|s| s.as_str()));
    read_scopes.extend(scope_map.identity_providers.read.iter().map(|s| s.as_str()));
    read_scopes.extend(scope_map.realms.read.iter().map(|s| s.as_str()));
    read_scopes.extend(scope_map.events.read.iter().map(|s| s.as_str()));
    read_scopes.extend(scope_map.tokens.read.iter().map(|s| s.as_str()));
    read_scopes.extend(scope_map.observability.read.iter().map(|s| s.as_str()));

    if required_scopes
        .iter()
        .any(|scope| read_scopes.contains(scope.as_str()))
    {
        return RoleGateKind::Read;
    }

    RoleGateKind::None
}

fn has_any_role(role_set: &std::collections::HashSet<&str>, required: &[String]) -> bool {
    required.iter().any(|role| role_set.contains(role.as_str()))
}
