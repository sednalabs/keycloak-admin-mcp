use axum::http::request::Parts;
use axum::http::Method;
use regex::Regex;
use mcp_toolkit_core::rmcp::handler::server::tool::Extension;
use mcp_toolkit_core::rmcp::handler::server::wrapper::Parameters;
use mcp_toolkit_core::rmcp::model::CallToolResult;
use mcp_toolkit_core::rmcp::tool;
use mcp_toolkit_core::rmcp::tool_router;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::errors::tool_error;
use crate::server::KcAdminMcp;
use crate::tools::shared::{auth_from_parts, require_roles_for_scopes, require_scopes};

const EVENTS_LIST_DATE_HINT: &str = "YYYY-MM-DD, epoch milliseconds, or ISO-8601 timestamp";

/// Event type filter for `events.list`.
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
#[serde(untagged)]
pub enum EventTypeArg {
    Single(String),
    Multiple(Vec<String>),
}

/// Arguments for `events.list`.
/// Required scopes: `keycloak-admin:events:read` (configurable); safety: read-only.
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
#[serde(rename_all = "camelCase")]
pub struct EventsListArgs {
    pub realm: String,
    #[serde(default)]
    pub client: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default, rename = "type")]
    pub event_type: Option<EventTypeArg>,
    #[serde(default)]
    pub date_from: Option<String>,
    #[serde(default)]
    pub date_to: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub first: Option<u32>,
    #[serde(default)]
    pub max: Option<u32>,
}

/// Arguments for `admin_events.list`.
/// Required scopes: `keycloak-admin:events:read` (configurable); safety: read-only.
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
#[serde(rename_all = "camelCase")]
pub struct AdminEventsListArgs {
    pub realm: String,
    #[serde(default)]
    pub auth_client: Option<String>,
    #[serde(default)]
    pub auth_user: Option<String>,
    #[serde(default)]
    pub auth_realm: Option<String>,
    #[serde(default)]
    pub auth_ip_address: Option<String>,
    #[serde(default)]
    pub resource_path: Option<String>,
    #[serde(default)]
    pub resource_types: Option<String>,
    #[serde(default)]
    pub operation_types: Option<String>,
    #[serde(default)]
    pub date_from: Option<String>,
    #[serde(default)]
    pub date_to: Option<String>,
    #[serde(default)]
    pub first: Option<u32>,
    #[serde(default)]
    pub max: Option<u32>,
}

/// Arguments for `events.clear` and `admin_events.clear`.
/// Required scopes: `keycloak-admin:events:admin` (configurable); safety: destructive (clears event records).
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
pub struct EventsClearArgs {
    pub realm: String,
    pub confirm: bool,
}

#[derive(Debug, Deserialize)]
struct UserEventRepresentation {
    #[serde(rename = "clientId")]
    client_id: Option<String>,
    details: Option<serde_json::Value>,
    error: Option<String>,
    #[serde(rename = "ipAddress")]
    ip_address: Option<String>,
    #[serde(rename = "realmId")]
    realm_id: Option<String>,
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
    time: Option<i64>,
    #[serde(rename = "type")]
    event_type: Option<String>,
    #[serde(rename = "userId")]
    user_id: Option<String>,
}

#[derive(Debug, Deserialize, serde::Serialize, JsonSchema)]
struct UserEventSummary {
    client_id: Option<String>,
    details: Option<serde_json::Value>,
    error: Option<String>,
    ip_address: Option<String>,
    realm_id: Option<String>,
    session_id: Option<String>,
    time: Option<i64>,
    event_type: Option<String>,
    user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdminEventRepresentation {
    #[serde(rename = "authDetails")]
    auth_details: Option<serde_json::Value>,
    error: Option<String>,
    #[serde(rename = "operationType")]
    operation_type: Option<String>,
    #[serde(rename = "realmId")]
    realm_id: Option<String>,
    representation: Option<String>,
    #[serde(rename = "resourcePath")]
    resource_path: Option<String>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    time: Option<i64>,
    details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, serde::Serialize, JsonSchema)]
struct AdminEventSummary {
    auth_details: Option<serde_json::Value>,
    error: Option<String>,
    operation_type: Option<String>,
    realm_id: Option<String>,
    representation: Option<String>,
    resource_path: Option<String>,
    resource_type: Option<String>,
    time: Option<i64>,
    details: Option<serde_json::Value>,
}

#[tool_router(router = tool_router_events, vis = "pub")]
impl KcAdminMcp {
    /// List user events in a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:events:read` (configurable); safety: read-only.
    #[tool(name = "events.list", description = "List user events in a realm.")]
    async fn events_list(
        &self,
        Parameters(args): Parameters<EventsListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.events.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let date_from = match normalize_events_list_date(args.date_from.as_deref()) {
            Ok(value) => value,
            Err(message) => {
                return Ok(tool_error("events.invalid_date", &message, &ctx.request_id))
            }
        };
        let date_to = match normalize_events_list_date(args.date_to.as_deref()) {
            Ok(value) => value,
            Err(message) => {
                return Ok(tool_error("events.invalid_date", &message, &ctx.request_id))
            }
        };

        let mut query = Vec::new();
        if let Some(client) = args.client {
            query.push(("client".to_string(), client));
        }
        if let Some(user) = args.user {
            query.push(("user".to_string(), user));
        }
        if let Some(event_type) = args.event_type {
            match event_type {
                EventTypeArg::Single(value) => query.push(("type".to_string(), value)),
                EventTypeArg::Multiple(values) => {
                    for value in values {
                        query.push(("type".to_string(), value));
                    }
                }
            }
        }
        if let Some(value) = date_from {
            query.push(("dateFrom".to_string(), value));
        }
        if let Some(value) = date_to {
            query.push(("dateTo".to_string(), value));
        }
        if let Some(ip_address) = args.ip_address {
            query.push(("ipAddress".to_string(), ip_address));
        }
        if let Some(first) = args.first {
            query.push(("first".to_string(), first.to_string()));
        }
        if let Some(max) = args.max {
            query.push(("max".to_string(), max.to_string()));
        }

        let path = format!("/admin/realms/{}/events", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, query, None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let events: Vec<UserEventSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<UserEventRepresentation>(item).ok())
                .map(|event| UserEventSummary {
                    client_id: event.client_id,
                    details: event.details,
                    error: event.error,
                    ip_address: event.ip_address,
                    realm_id: event.realm_id,
                    session_id: event.session_id,
                    time: event.time,
                    event_type: event.event_type,
                    user_id: event.user_id,
                })
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "events": events })))
    }

    /// List admin events in a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:events:read` (configurable); safety: read-only.
    #[tool(
        name = "admin_events.list",
        description = "List admin events in a realm."
    )]
    async fn admin_events_list(
        &self,
        Parameters(args): Parameters<AdminEventsListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.events.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let date_from = match normalize_events_list_date(args.date_from.as_deref()) {
            Ok(value) => value,
            Err(message) => {
                return Ok(tool_error("events.invalid_date", &message, &ctx.request_id))
            }
        };
        let date_to = match normalize_events_list_date(args.date_to.as_deref()) {
            Ok(value) => value,
            Err(message) => {
                return Ok(tool_error("events.invalid_date", &message, &ctx.request_id))
            }
        };

        let mut query = Vec::new();
        if let Some(value) = args.auth_client {
            query.push(("authClient".to_string(), value));
        }
        if let Some(value) = args.auth_user {
            query.push(("authUser".to_string(), value));
        }
        if let Some(value) = args.auth_realm {
            query.push(("authRealm".to_string(), value));
        }
        if let Some(value) = args.auth_ip_address {
            query.push(("authIpAddress".to_string(), value));
        }
        if let Some(value) = args.resource_path {
            query.push(("resourcePath".to_string(), value));
        }
        if let Some(value) = args.resource_types {
            query.push(("resourceTypes".to_string(), value));
        }
        if let Some(value) = args.operation_types {
            query.push(("operationTypes".to_string(), value));
        }
        if let Some(value) = date_from {
            query.push(("dateFrom".to_string(), value));
        }
        if let Some(value) = date_to {
            query.push(("dateTo".to_string(), value));
        }
        if let Some(first) = args.first {
            query.push(("first".to_string(), first.to_string()));
        }
        if let Some(max) = args.max {
            query.push(("max".to_string(), max.to_string()));
        }

        let path = format!("/admin/realms/{}/admin-events", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, query, None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let events: Vec<AdminEventSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<AdminEventRepresentation>(item).ok())
                .map(|event| AdminEventSummary {
                    auth_details: event.auth_details,
                    error: event.error,
                    operation_type: event.operation_type,
                    realm_id: event.realm_id,
                    representation: event.representation,
                    resource_path: event.resource_path,
                    resource_type: event.resource_type,
                    time: event.time,
                    details: event.details,
                })
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "events": events })))
    }

    /// Clear user events in a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:events:admin` (configurable); safety: destructive.
    #[tool(
        name = "events.clear",
        description = "Clear user events in a realm (confirm=true)."
    )]
    async fn events_clear(
        &self,
        Parameters(args): Parameters<EventsClearArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.events.admin;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }
        if !args.confirm {
            return Ok(tool_error(
                "events.confirm_required",
                "confirm=true is required to clear events.",
                &ctx.request_id,
            ));
        }

        let path = format!("/admin/realms/{}/events", args.realm);
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Clear admin events in a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:events:admin` (configurable); safety: destructive.
    #[tool(
        name = "admin_events.clear",
        description = "Clear admin events in a realm (confirm=true)."
    )]
    async fn admin_events_clear(
        &self,
        Parameters(args): Parameters<EventsClearArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.events.admin;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }
        if !args.confirm {
            return Ok(tool_error(
                "events.confirm_required",
                "confirm=true is required to clear admin events.",
                &ctx.request_id,
            ));
        }

        let path = format!("/admin/realms/{}/admin-events", args.realm);
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }
}

fn normalize_events_list_date(value: Option<&str>) -> Result<Option<String>, String> {
    let value = match value {
        Some(value) => value.trim(),
        None => return Ok(None),
    };
    if value.is_empty() {
        return Ok(None);
    }

    let epoch_re = Regex::new(r"^\d+$").expect("valid regex");
    if epoch_re.is_match(value) {
        return Ok(Some(value.to_string()));
    }

    let date_re = Regex::new(r"^\d{4}-\d{2}-\d{2}$").expect("valid regex");
    if date_re.is_match(value) {
        return Ok(Some(value.to_string()));
    }

    if value
        .chars()
        .next()
        .map(|ch| ch.is_ascii_digit())
        .unwrap_or(false)
        && value.contains('T')
    {
        let parsed = OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|_| format!("Invalid date (expected {EVENTS_LIST_DATE_HINT})."))?;
        let millis = parsed.unix_timestamp_nanos() / 1_000_000;
        return Ok(Some(millis.to_string()));
    }

    Err(format!("Invalid date (expected {EVENTS_LIST_DATE_HINT})."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Path;
    use axum::routing::get;
    use axum::Json;
    use serde_json::json;

    use crate::test_support::{
        auth_context, build_config, build_server, parts_with_auth, TestServer,
    };

    async fn events_handler(Path(realm): Path<String>) -> Json<serde_json::Value> {
        assert_eq!(realm, "alpha");
        Json(json!([
            {
                "clientId": "client-1",
                "details": {"key": "value"},
                "error": null,
                "ipAddress": "127.0.0.1",
                "realmId": "alpha",
                "sessionId": "sess-1",
                "time": 1710000000,
                "type": "LOGIN",
                "userId": "user-1"
            }
        ]))
    }

    #[tokio::test]
    async fn events_list_returns_structured_output() {
        let router = axum::Router::new().route("/admin/realms/{realm}/events", get(events_handler));
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.events.read.clone());
        let parts = parts_with_auth(ctx);
        let args = EventsListArgs {
            realm: "alpha".to_string(),
            client: None,
            user: None,
            event_type: None,
            date_from: None,
            date_to: None,
            ip_address: None,
            first: None,
            max: None,
        };

        let result = mcp
            .events_list(
                mcp_toolkit_core::rmcp::handler::server::wrapper::Parameters(args),
                mcp_toolkit_core::rmcp::handler::server::tool::Extension(parts),
            )
            .await
            .expect("events list result");

        let structured = result.structured_content.expect("structured content");

        assert_eq!(
            structured,
            json!({
                "events": [
                    {
                        "client_id": "client-1",
                        "details": {"key": "value"},
                        "error": null,
                        "ip_address": "127.0.0.1",
                        "realm_id": "alpha",
                        "session_id": "sess-1",
                        "time": 1710000000,
                        "event_type": "LOGIN",
                        "user_id": "user-1"
                    }
                ]
            })
        );

        server.shutdown();
    }
}
