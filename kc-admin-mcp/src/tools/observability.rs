use crate::errors::tool_error;
use crate::server::KcAdminMcp;
use crate::tools::shared::{auth_from_parts, require_roles_for_scopes, require_scopes};
use axum::http::request::Parts;
use mcp_toolkit_core::rmcp::handler::server::tool::Extension;
use mcp_toolkit_core::rmcp::handler::server::wrapper::Parameters;
use mcp_toolkit_core::rmcp::model::CallToolResult;
use mcp_toolkit_core::rmcp::tool;
use mcp_toolkit_core::rmcp::tool_router;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

/// Arguments for `audit.list`.
/// Required scopes: `keycloak-admin:observability:read` (configurable); safety: read-only.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AuditListArgs {
    #[serde(default)]
    pub limit: Option<u32>,
}

#[tool_router(router = tool_router_observability, vis = "pub")]
impl KcAdminMcp {
    /// Return server status and a config snapshot.
    /// Local-only; does not call the gateway.
    /// Required scopes: `keycloak-admin:observability:read` (configurable); safety: read-only but exposes configuration metadata.
    #[tool(
        name = "status.get",
        description = "Get server status and config summary."
    )]
    async fn status_get(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.observability.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let uptime_s = self.started_at.elapsed().as_secs();
        let auth_mode = match self.config.auth.mode {
            crate::config::AuthMode::Introspection => "introspection",
            crate::config::AuthMode::Jwks => "jwks",
        };
        let auth_method = match self.config.auth.introspection_auth_method {
            crate::config::ClientAuthMethod::ClientSecretBasic => "client_secret_basic",
            crate::config::ClientAuthMethod::ClientSecretPost => "client_secret_post",
        };
        let mtls_mode = match self.config.auth.mtls_mode {
            crate::config::MtlsMode::Disabled => "disabled",
            crate::config::MtlsMode::Native => "native",
            crate::config::MtlsMode::ProxyHeader => "proxy",
        };

        let scope_map = json!({
            "users": {
                "read": &self.config.scope_map.users.read,
                "write": &self.config.scope_map.users.write,
            },
            "groups": {
                "read": &self.config.scope_map.groups.read,
                "write": &self.config.scope_map.groups.write,
            },
            "roles": {
                "read": &self.config.scope_map.roles.read,
                "write": &self.config.scope_map.roles.write,
            },
            "clients": {
                "read": &self.config.scope_map.clients.read,
                "write": &self.config.scope_map.clients.write,
                "secrets": &self.config.scope_map.clients.secrets,
            },
            "client_scopes": {
                "read": &self.config.scope_map.client_scopes.read,
                "write": &self.config.scope_map.client_scopes.write,
            },
            "identity_providers": {
                "read": &self.config.scope_map.identity_providers.read,
                "write": &self.config.scope_map.identity_providers.write,
            },
            "realms": {
                "read": &self.config.scope_map.realms.read,
                "write": &self.config.scope_map.realms.write,
                "admin": &self.config.scope_map.realms.admin,
            },
            "events": {
                "read": &self.config.scope_map.events.read,
                "admin": &self.config.scope_map.events.admin,
            },
            "tokens": {
                "read": &self.config.scope_map.tokens.read,
            },
            "observability": {
                "read": &self.config.scope_map.observability.read,
            },
        });

        let config_snapshot = json!({
            "bind_addr": &self.config.bind_addr,
            "resource_url": &self.config.resource_url,
            "resource_metadata_url": &self.config.resource_metadata_url,
            "authorization_servers": &self.config.authorization_servers,
            "scopes_supported": &self.config.scopes_supported,
            "scope_map": scope_map,
            "auth_mode": auth_mode,
            "issuer": &self.config.auth.issuer,
            "audience": &self.config.auth.audience,
            "clock_skew_seconds": self.config.auth.clock_skew_seconds,
            "introspection_url": &self.config.auth.introspection_url,
            "introspection_auth_method": auth_method,
            "jwks_url": &self.config.auth.jwks_url,
            "dpop_required": self.config.auth.dpop_required,
            "mtls_mode": mtls_mode,
            "mtls_client_cert_header": &self.config.auth.mtls_client_cert_header,
            "server_tls_cert_configured": self.config.server_tls.cert_pem.is_some(),
            "server_tls_key_configured": self.config.server_tls.key_pem.is_some(),
            "server_tls_client_ca_configured": self.config.server_tls.client_ca_pem.is_some(),
            "gateway_base_url": &self.config.gateway.base_url,
            "gateway_timeout_ms": self.config.gateway.request_timeout.as_millis(),
            "gateway_tls_ca_configured": self.config.gateway.tls_ca_pem.is_some(),
            "gateway_tls_client_cert_configured": self.config.gateway.tls_client_cert_pem.is_some(),
            "gateway_tls_client_key_configured": self.config.gateway.tls_client_key_pem.is_some(),
            "keycloak_base_url": &self.config.keycloak_base_url,
            "keycloak_admin_realm": &self.config.keycloak_admin_realm,
            "keycloak_client_id": &self.config.keycloak_client_id,
            "enable_secret_tools": self.config.enable_secret_tools,
            "audit_log_max": self.config.audit_log_max,
            "audit_log_path": &self.config.audit_log_path,
            "audit_checkpoint_path": &self.config.audit_checkpoint_path,
            "audit_log_max_bytes": self.config.audit_log_max_bytes,
            "audit_log_max_files": self.config.audit_log_max_files,
        });

        Ok(CallToolResult::structured(json!({
            "status": "ok",
            "uptime_s": uptime_s,
            "config": config_snapshot,
        })))
    }

    /// Return in-memory metrics counters and histograms.
    /// Local-only; does not call the gateway.
    /// Required scopes: `keycloak-admin:observability:read` (configurable); safety: read-only.
    #[tool(name = "metrics.get", description = "Get in-memory metrics snapshot.")]
    async fn metrics_get(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.observability.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let uptime_s = self.started_at.elapsed().as_secs();
        let snapshot = self.metrics.snapshot();
        Ok(CallToolResult::structured(json!({
            "uptime_s": uptime_s,
            "auth_rejects_total": snapshot.auth_rejects_total,
            "request_timeouts_total": snapshot.request_timeouts_total,
            "tool_calls_total": snapshot.tool_calls_total,
            "tool_call_duration_ms": snapshot.tool_call_duration_ms,
        })))
    }

    /// List recent audit entries from the in-memory ring buffer.
    /// Local-only; does not call the gateway.
    /// Required scopes: `keycloak-admin:observability:read` (configurable); safety: read-only.
    #[tool(
        name = "audit.list",
        description = "List recent tool invocations (in-memory ring buffer)."
    )]
    async fn audit_list(
        &self,
        Parameters(args): Parameters<AuditListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.observability.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let limit = args.limit.unwrap_or(50) as usize;
        let entries = self.audit_log.snapshot(limit);
        Ok(CallToolResult::structured(json!({ "entries": entries })))
    }

    /// Write an audit hash-chain checkpoint to disk and return the latest hash.
    /// Local-only; does not call the gateway.
    /// Required scopes: `keycloak-admin:observability:read` (configurable); safety: writes checkpoint files.
    #[tool(
        name = "audit.checkpoint",
        description = "Write a hash-chain checkpoint file and return the latest hash."
    )]
    async fn audit_checkpoint(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.observability.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let checkpoint = match self.audit_log.checkpoint() {
            Ok(value) => value,
            Err(err) => {
                return Ok(tool_error(
                    "audit.checkpoint_failed",
                    &format!("Checkpoint failed: {err}"),
                    &ctx.request_id,
                ))
            }
        };
        Ok(CallToolResult::structured(json!({
            "schema_version": checkpoint.schema_version,
            "ts": checkpoint.ts,
            "last_hash": checkpoint.last_hash,
            "log_path": checkpoint.log_path,
            "state_path": checkpoint.state_path,
            "checkpoint_path": checkpoint.checkpoint_path,
        })))
    }
}
