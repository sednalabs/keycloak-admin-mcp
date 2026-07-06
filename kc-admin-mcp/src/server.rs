//! # MCP Server Logic
//!
//! Implements the MCP protocol handlers and tool routing for the Keycloak Admin server.
//!
//! ## Rationale
//! This module acts as the orchestrator for all Keycloak admin tool calls. It defines
//! the tool surface and ensures that every call is audited and its outcome recorded.
//! It strictly delegates all administrative work to the `kc-admin-gateway`.
//!
//! ## Security Boundaries
//! * **Tool Gating**: Only registered tools can be called.
//! * **Identity Context**: Injects the `AuthContext` into every tool call.
//! * **Audit Enforcement**: Ensures that every tool execution is recorded in the audit log.
//!
//! ## References
//! * **DESIGN**: `docs/design/admin-mcp-architecture.md`

use std::sync::Arc;
use std::time::Instant;

use mcp_toolkit_core::{
    notifications::{ToolListTracker, ToolListUpdate},
    rmcp_models,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Implementation, ListResourcesResult, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams, ReadResourceResult,
    Resource, ResourceContents, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler};
use std::future::Future;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::audit::{AuditActor, AuditEntry, AuditLog, AuditOutcome, AuditTool};
use crate::auth::AuthContext;
use crate::config::Config;
use crate::gateway::GatewayClient;
use crate::log_context;
use crate::logging::LOG_TARGET_ACCESS;
use crate::metrics::Metrics;
use crate::provenance::{build_attestation_envelope, RuntimeAdmissionExtension, RuntimeProvenance};
use axum::http::request::Parts;
use rmcp::ErrorData;

use crate::tools::bundles::TOOL_BUNDLES;

const LOGGING_SCHEMA_URI: &str = "kc-admin://logging/schema";
const TOOL_BUNDLES_URI: &str = "kc-admin://tools/bundles";
const STATUS_URI: &str = "kc-admin://status";
const ATTEST_URI: &str = "kc-admin://attest";

/// MCP server implementation that exposes the tool router and metrics/audit logging.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone)]
pub struct KcAdminMcp {
    pub config: Arc<Config>,
    pub gateway: GatewayClient,
    pub started_at: Instant,
    pub metrics: Arc<Metrics>,
    pub audit_log: Arc<AuditLog>,
    pub provenance: Arc<RuntimeProvenance>,
    pub runtime_admission: RuntimeAdmissionExtension,
    tool_router: ToolRouter<KcAdminMcp>,
    tool_list_tracker: Arc<ToolListTracker>,
}

impl KcAdminMcp {
    /// Construct a new MCP server handler with gateway/metrics/audit dependencies.
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
        config: Arc<Config>,
        gateway: GatewayClient,
        started_at: Instant,
        metrics: Arc<Metrics>,
        audit_log: Arc<AuditLog>,
        tool_list_tracker: Arc<ToolListTracker>,
        provenance: Arc<RuntimeProvenance>,
        runtime_admission: RuntimeAdmissionExtension,
    ) -> Self {
        let tool_router = Self::tool_router_users()
            + Self::tool_router_groups()
            + Self::tool_router_clients()
            + Self::tool_router_roles()
            + Self::tool_router_client_scopes()
            + Self::tool_router_identity_providers()
            + Self::tool_router_realms()
            + Self::tool_router_events()
            + Self::tool_router_observability();
        Self {
            config,
            gateway,
            started_at,
            metrics,
            audit_log,
            provenance,
            runtime_admission,
            tool_router,
            tool_list_tracker,
        }
    }

    fn effective_tools(&self) -> Vec<rmcp::model::Tool> {
        let mut tools = self.tool_router.list_all();
        if !self.config.enable_secret_tools {
            tools.retain(|tool| !tool.name.starts_with("clients.secrets."));
        }
        tools
    }

    async fn maybe_notify_tool_list_changed(
        &self,
        session_id: Option<&str>,
        peer: &rmcp::service::Peer<RoleServer>,
    ) {
        let session_id = session_id.map(str::trim).filter(|value| !value.is_empty());
        let Some(session_id) = session_id else {
            return;
        };
        let tool_names = self.effective_tools().into_iter().map(|tool| tool.name);
        let update = self.tool_list_tracker.observe(session_id, tool_names);
        if matches!(update, ToolListUpdate::Changed { .. }) {
            if let Err(err) = peer.notify_tool_list_changed().await {
                tracing::debug!(error = %err, session_id, "tools list_changed notification failed");
            }
        }
    }
}

impl ServerHandler for KcAdminMcp {
    /// Return server metadata, versioning, and capabilities.
    fn get_info(&self) -> ServerInfo {
        rmcp_models::server_info(
            ProtocolVersion::V_2024_11_05,
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_tool_list_changed()
                .build(),
            Implementation::from_build_env(),
            Some(
                "Keycloak admin MCP server (Rust). Auth enforced; tools delegate to kc-admin-gateway.".to_string(),
            ),
        )
    }

    /// List all registered tools from the tool router.
    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_ {
        let tools = self.effective_tools();
        if let Some(session_id) = log_context::current().and_then(|ctx| ctx.session_id) {
            let _ = self
                .tool_list_tracker
                .observe(&session_id, tools.iter().map(|tool| tool.name.as_ref()));
        }
        std::future::ready(Ok(ListToolsResult {
            meta: None,
            tools,
            next_cursor: None,
        }))
    }

    /// Execute a tool call via the internal router.
    ///
    /// # Security
    /// * **Auditing**: Records metrics, access logs, and audit entries for every execution.
    /// * **Identity**: Propagates the caller's identity to the audit entry.
    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_ {
        let start = Instant::now();
        let tool_name = request.name.to_string();
        let metrics = self.metrics.clone();
        let audit_log = self.audit_log.clone();
        let (request_id, actor) = extract_audit_actor(&context);
        let session_id = log_context::current().and_then(|ctx| ctx.session_id);
        let peer = context.peer.clone();
        let tool_context = ToolCallContext::new(self, request, context);

        async move {
            let result =
                log_context::with_tool(&tool_name, self.tool_router.call(tool_context)).await;
            let duration_ms = start.elapsed().as_millis() as u64;
            let status = match &result {
                Ok(value) => match value.is_error {
                    Some(true) => "error",
                    _ => "success",
                },
                Err(_) => "error",
            };

            metrics.record_tool_call(&tool_name, status, duration_ms);
            tracing::info!(
                target: LOG_TARGET_ACCESS,
                tool = %tool_name,
                status = status,
                duration_ms = duration_ms,
                "tool.call"
            );

            let entry = AuditEntry {
                schema_version: "v1".to_string(),
                event_type: "tool.call".to_string(),
                ts: OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".to_string()),
                request_id,
                prev_hash: None,
                hash: None,
                actor,
                tool: AuditTool {
                    name: tool_name.clone(),
                },
                outcome: AuditOutcome {
                    status: status.to_string(),
                    duration_ms,
                },
            };
            audit_log.record(entry);

            if let Ok(payload) = &result {
                let is_error = payload.is_error.unwrap_or(false);
                if !is_error {
                    self.maybe_notify_tool_list_changed(session_id.as_deref(), &peer)
                        .await;
                }
            }

            result
        }
    }

    /// List available resources, including the logging schema and tool bundles.
    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + Send + '_ {
        let mut resources = Vec::new();

        // Logging Schema
        let schema = logging_schema();
        let schema_size = serde_json::to_string(&schema).map(|s| s.len() as u32).ok();
        resources.push(Resource::new(
            rmcp::model::RawResource {
                uri: LOGGING_SCHEMA_URI.to_string(),
                name: "kc-admin-logging-schema".to_string(),
                title: Some("KC Admin MCP logging schema".to_string()),
                description: Some(
                    "Event names and payload shapes emitted via MCP logging notifications."
                        .to_string(),
                ),
                mime_type: Some("application/json".to_string()),
                size: schema_size,
                icons: None,
                meta: None,
            },
            None,
        ));

        // Tool Bundles
        let bundles_size = serde_json::to_string(&TOOL_BUNDLES)
            .map(|s| s.len() as u32)
            .ok();
        resources.push(Resource::new(
            rmcp::model::RawResource {
                uri: TOOL_BUNDLES_URI.to_string(),
                name: "kc-admin-tool-bundles".to_string(),
                title: Some("KC Admin Tool Bundles".to_string()),
                description: Some(
                    "Logical grouping of tools for dynamic injection and least-privilege discovery."
                        .to_string(),
                ),
                mime_type: Some("application/json".to_string()),
                size: bundles_size,
                icons: None,
                meta: None,
            },
            None,
        ));

        resources.push(Resource::new(
            rmcp::model::RawResource {
                uri: STATUS_URI.to_string(),
                name: "kc-admin-status".to_string(),
                title: Some("KC Admin MCP status".to_string()),
                description: Some("Server status and runtime provenance (JSON).".to_string()),
                mime_type: Some("application/json".to_string()),
                size: None,
                icons: None,
                meta: None,
            },
            None,
        ));

        resources.push(Resource::new(
            rmcp::model::RawResource {
                uri: ATTEST_URI.to_string(),
                name: "kc-admin-attest".to_string(),
                title: Some("KC Admin MCP attestation".to_string()),
                description: Some(
                    "Fleet v2 attestation envelope for this running server.".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
                size: None,
                icons: None,
                meta: None,
            },
            None,
        ));

        std::future::ready(Ok(ListResourcesResult {
            resources,
            next_cursor: None,
            meta: None,
        }))
    }

    /// Read resource content for a given URI.
    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResult, rmcp::ErrorData>> + Send + '_ {
        let (uri, text) = match request.uri.as_str() {
            LOGGING_SCHEMA_URI => {
                let schema = logging_schema();
                (
                    LOGGING_SCHEMA_URI,
                    serde_json::to_string_pretty(&schema).unwrap_or_else(|_| "{}".to_string()),
                )
            }
            TOOL_BUNDLES_URI => (
                TOOL_BUNDLES_URI,
                serde_json::to_string_pretty(&TOOL_BUNDLES).unwrap_or_else(|_| "[]".to_string()),
            ),
            STATUS_URI => {
                let payload = serde_json::json!({
                    "status": "ok",
                    "server": "kc-admin-mcp",
                    "version": self.provenance.build.server_version,
                    "timestamp": now_rfc3339(),
                    "provenance": &*self.provenance,
                    "startup_admission": &self.runtime_admission,
                });
                (
                    STATUS_URI,
                    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string()),
                )
            }
            ATTEST_URI => {
                let payload = build_attestation_envelope(&self.provenance, &self.runtime_admission);
                (
                    ATTEST_URI,
                    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string()),
                )
            }
            _ => {
                return std::future::ready(Err(ErrorData::resource_not_found(
                    "resource not found",
                    None,
                )))
            }
        };

        let contents = ResourceContents::TextResourceContents {
            uri: uri.to_string(),
            mime_type: Some("application/json".to_string()),
            text,
            meta: None,
        };
        std::future::ready(Ok(rmcp_models::read_resource_result(vec![contents])))
    }
}

fn logging_schema() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "notes": [
            "All MCP log payloads include an `event` field.",
            "Payloads are redacted and size-capped before emission."
        ],
        "events": [
            {
                "name": "session.initialize",
                "fields": {
                    "protocol_version": "string",
                    "client_name": "string",
                    "client_version": "string"
                }
            },
            {"name": "session.initialized", "fields": {}},
            {"name": "session.disconnect", "fields": {"error": "boolean", "error_type": "string"}},
            {"name": "tool.call.start", "fields": {"tool_name": "string", "arg_keys": "string[]"}},
            {"name": "tool.call.error", "fields": {"tool_name": "string", "error": "string", "reason": "string", "retry_after_s": "number"}},
            {"name": "tool.call.finish", "fields": {"tool_name": "string", "duration_ms": "number", "error": "boolean"}},
            {"name": "discovery.tools.list.*", "fields": {"duration_ms": "number", "count": "number", "error": "boolean"}},
            {"name": "discovery.resources.list.*", "fields": {"duration_ms": "number", "count": "number", "error": "boolean"}},
            {"name": "discovery.resource_templates.list.*", "fields": {"duration_ms": "number", "count": "number", "error": "boolean"}},
            {"name": "discovery.prompts.list.*", "fields": {"duration_ms": "number", "count": "number", "error": "boolean"}},
            {"name": "resource.read.*", "fields": {"uri": "string", "duration_ms": "number", "error": "boolean"}},
            {"name": "resource.subscribe.*", "fields": {"uri": "string", "duration_ms": "number", "error": "boolean"}},
            {"name": "resource.unsubscribe.*", "fields": {"uri": "string", "duration_ms": "number", "error": "boolean"}},
            {"name": "prompt.render.*", "fields": {"prompt_name": "string", "duration_ms": "number", "error": "boolean"}}
        ]
    })
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn extract_audit_actor(context: &RequestContext<RoleServer>) -> (String, Option<AuditActor>) {
    let request_id = context.id.to_string();
    let parts = context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<AuthContext>().cloned());
    match parts {
        Some(auth_ctx) => {
            let actor = AuditActor {
                subject: auth_ctx.subject.clone(),
                client_id: auth_ctx.client_id.clone(),
                scopes: auth_ctx.scopes.clone(),
                roles: auth_ctx.roles.clone(),
                actor_id: auth_ctx.actor_id.clone(),
            };
            (auth_ctx.request_id, Some(actor))
        }
        None => (request_id, None),
    }
}

#[cfg(test)]
mod tests {
    use super::KcAdminMcp;
    use mcp_toolkit_testing::assert_tool_schema_snapshot;

    #[test]
    fn tool_schema_snapshot_contract_is_stable() {
        let tools = (KcAdminMcp::tool_router_users()
            + KcAdminMcp::tool_router_groups()
            + KcAdminMcp::tool_router_clients()
            + KcAdminMcp::tool_router_roles()
            + KcAdminMcp::tool_router_client_scopes()
            + KcAdminMcp::tool_router_identity_providers()
            + KcAdminMcp::tool_router_realms()
            + KcAdminMcp::tool_router_events()
            + KcAdminMcp::tool_router_observability())
        .list_all();
        let snapshot_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("spec/tool_schema_snapshot.v1.json");
        assert_tool_schema_snapshot(snapshot_path, &tools);
    }
}
