use std::collections::HashMap;

use axum::http::request::Parts;
use axum::http::Method;
use mcp_toolkit_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_toolkit_core::rmcp::handler::server::tool::Extension;
use mcp_toolkit_core::rmcp::handler::server::wrapper::Parameters;
use mcp_toolkit_core::rmcp::model::CallToolResult;
use mcp_toolkit_core::rmcp::tool;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::errors::tool_error;
use crate::server::KcAdminMcp;
use crate::tools::shared::{auth_from_parts, require_roles_for_scopes, require_scopes};

const MAX_DESC_LEN: usize = 1024;
const CLIENT_REG_POLICY_COMPONENT_TYPE: &str =
    "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy";
const DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER: &str = "allowed-client-templates";
const CONFIG_ALLOWED_CLIENT_SCOPES_KEYS: [&str; 2] =
    ["allowedClientScopes", "allowed-client-scopes"];
const CONFIG_ALLOW_DEFAULT_SCOPES_KEYS: [&str; 2] = ["allowDefaultScopes", "allow-default-scopes"];

/// Arguments for realm-scoped tools.
/// Required scopes vary by tool (`realm:read`, `realm:write`, or `realm:admin`); safety varies by tool.
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
pub struct RealmArgs {
    pub realm: String,
}

/// Arguments for `client_initial_access.create`.
/// Required scopes: `keycloak-admin:realm:admin` (configurable); safety: creates initial access tokens.
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
pub struct ClientInitialAccessCreateArgs {
    pub realm: String,
    #[serde(default)]
    pub count: Option<u32>,
    #[serde(default)]
    pub expiration: Option<u32>,
}

/// Arguments for `client_initial_access.delete`.
/// Required scopes: `keycloak-admin:realm:admin` (configurable); safety: destructive.
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
pub struct ClientInitialAccessDeleteArgs {
    pub realm: String,
    pub id: String,
}

/// Arguments for `realm.events.config.set`.
/// Required scopes: `keycloak-admin:realm:write` (configurable); safety: writes realm event configuration.
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
pub struct RealmEventsConfigArgs {
    pub realm: String,
    pub config: RealmEventsConfig,
}

/// Arguments for `realm.smtp.test`.
/// Required scopes: `keycloak-admin:realm:write` (configurable); safety: initiates SMTP connectivity checks.
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
pub struct RealmSmtpTestArgs {
    pub realm: String,
    pub settings: HashMap<String, serde_json::Value>,
}

/// Captures inputs for updating a client registration policy component.
///
/// # Errors
/// * The handler returns an error if required fields are missing or malformed.
///
/// # Security
/// * Writes registration policy configuration via the gateway.
///
/// # Caveats
/// * `allowed_scopes` is serialized into Keycloak component config list entries.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClientRegistrationPolicyUpdateArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    #[serde(default)]
    pub allow_default_scopes: Option<bool>,
}

/// Captures inputs for creating a client registration policy component.
///
/// # Errors
/// * The handler returns an error if required fields are missing or malformed.
///
/// # Security
/// * Creates registration policy configuration via the gateway.
///
/// # Caveats
/// * `allowed_scopes` is serialized into Keycloak component config list entries.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClientRegistrationPolicyCreateArgs {
    pub realm: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    #[serde(default)]
    pub allow_default_scopes: Option<bool>,
}

/// Captures inputs for deleting a client registration policy component.
///
/// # Errors
/// * The handler returns an error if required fields are missing or malformed.
///
/// # Security
/// * Deletes registration policy configuration via the gateway.
///
/// # Caveats
/// * When multiple components match, the handler requires a more specific selector.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClientRegistrationPolicyDeleteArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub provider_id: Option<String>,
}

/// Captures selectors for listing configured client registration policies.
///
/// # Errors
/// * The handler returns an error if the gateway request fails.
///
/// # Security
/// * Reads registration policy configuration through the least-privilege gateway.
///
/// # Caveats
/// * Omitting every selector lists all configured registration policy components.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClientRegistrationPolicyListArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub provider_id: Option<String>,
}

/// Captures selectors for fetching one configured client registration policy.
///
/// # Errors
/// * The handler returns an error if the gateway request fails.
///
/// # Security
/// * Reads registration policy configuration through the least-privilege gateway.
///
/// # Caveats
/// * Omitting every selector targets the default Allowed Client Scopes provider.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClientRegistrationPolicyGetArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub provider_id: Option<String>,
}

/// Client scope category for realm default scopes.
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
#[serde(rename_all = "lowercase")]
pub enum DefaultScopeKind {
    Default,
    Optional,
}

/// Arguments for `realm.default_scopes.list`.
/// Required scopes: `keycloak-admin:realm:admin` (configurable); safety: read-only.
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
pub struct RealmDefaultScopesListArgs {
    pub realm: String,
    pub kind: DefaultScopeKind,
}

/// Arguments for `realm.default_scopes.add`.
/// Required scopes: `keycloak-admin:realm:admin` (configurable); safety: destructive.
///
/// Notes:
/// - Keycloak models "realm default scopes" as a list of client scope IDs. Callers can provide
///   either an explicit `scope_id` or a `scope_name` to resolve.
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
pub struct RealmDefaultScopesAddArgs {
    pub realm: String,
    pub kind: DefaultScopeKind,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub scope_name: Option<String>,
}

/// Arguments for `realm.default_scopes.remove`.
/// Required scopes: `keycloak-admin:realm:admin` (configurable); safety: destructive.
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
pub struct RealmDefaultScopesRemoveArgs {
    pub realm: String,
    pub kind: DefaultScopeKind,
    pub scope_id: String,
}

/// Payload for `realm.events.config.set`.
/// Required scopes: `keycloak-admin:realm:write` (configurable); safety: writes realm event configuration.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Deserialize, serde::Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RealmEventsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_expiration: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_listeners: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled_event_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_events_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_events_details_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RealmRepresentation {
    id: Option<String>,
    realm: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthFlowRepresentation {
    id: Option<String>,
    alias: Option<String>,
    description: Option<String>,
    #[serde(rename = "providerId")]
    provider_id: Option<String>,
    #[serde(rename = "topLevel")]
    top_level: Option<bool>,
    #[serde(rename = "builtIn")]
    built_in: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RealmKeyRepresentation {
    #[serde(rename = "providerId")]
    provider_id: Option<String>,
    #[serde(rename = "providerPriority")]
    provider_priority: Option<i64>,
    kid: Option<String>,
    status: Option<String>,
    #[serde(rename = "type")]
    key_type: Option<String>,
    algorithm: Option<String>,
    #[serde(rename = "validTo")]
    valid_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RealmKeysResponse {
    active: Option<HashMap<String, String>>,
    keys: Option<Vec<RealmKeyRepresentation>>,
}

#[derive(Debug, Deserialize)]
struct ClientInitialAccessRepresentation {
    id: Option<String>,
    timestamp: Option<i64>,
    expiration: Option<i64>,
    count: Option<i64>,
    #[serde(rename = "remainingCount")]
    remaining_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ClientScopeRepresentation {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    protocol: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct ClientScopeSummary {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    protocol: Option<String>,
}

impl From<ClientScopeRepresentation> for ClientScopeSummary {
    fn from(value: ClientScopeRepresentation) -> Self {
        Self {
            id: value.id,
            name: value.name,
            description: value
                .description
                .map(|value| value.chars().take(MAX_DESC_LEN).collect()),
            protocol: value.protocol,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ClientRegistrationPolicyProvider {
    id: Option<String>,
    #[serde(rename = "helpText")]
    help_text: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct RealmSummary {
    id: Option<String>,
    realm: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct AuthFlowSummary {
    id: Option<String>,
    alias: Option<String>,
    description: Option<String>,
    provider_id: Option<String>,
    top_level: Option<bool>,
    built_in: Option<bool>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct RealmKeySummary {
    provider_id: Option<String>,
    provider_priority: Option<i64>,
    kid: Option<String>,
    status: Option<String>,
    key_type: Option<String>,
    algorithm: Option<String>,
    valid_to: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct RealmKeysSummary {
    active: Option<HashMap<String, String>>,
    keys: Vec<RealmKeySummary>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct ClientInitialAccessSummary {
    id: Option<String>,
    timestamp: Option<i64>,
    expiration: Option<i64>,
    count: Option<i64>,
    remaining_count: Option<i64>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct ClientRegistrationPolicyProviderSummary {
    id: Option<String>,
    help_text: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, JsonSchema, PartialEq)]
struct ClientRegistrationPolicySummary {
    id: Option<String>,
    name: Option<String>,
    provider_id: Option<String>,
    provider_type: Option<String>,
    parent_id: Option<String>,
    allowed_scopes: Vec<String>,
    allow_default_scopes: Option<bool>,
    config: serde_json::Value,
}

mod core;
mod events;
mod registration;
mod scopes;

impl KcAdminMcp {
    pub fn tool_router_realms() -> ToolRouter<KcAdminMcp> {
        Self::tool_router_realms_core()
            + Self::tool_router_realms_scopes()
            + Self::tool_router_realms_events()
            + Self::tool_router_realms_registration()
    }
}
fn realm_default_scopes_path(realm: &str, kind: &DefaultScopeKind) -> String {
    let suffix = match kind {
        DefaultScopeKind::Default => "default-default-client-scopes",
        DefaultScopeKind::Optional => "default-optional-client-scopes",
    };
    format!("/admin/realms/{}/{}", realm, suffix)
}

fn realm_default_scope_member_path(realm: &str, kind: &DefaultScopeKind, scope_id: &str) -> String {
    let suffix = match kind {
        DefaultScopeKind::Default => "default-default-client-scopes",
        DefaultScopeKind::Optional => "default-optional-client-scopes",
    };
    format!("/admin/realms/{}/{}/{}", realm, suffix, scope_id)
}

async fn resolve_client_scope_id(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    scope_id: Option<&String>,
    scope_name: Option<&String>,
) -> Result<Option<String>, crate::McpError> {
    if let Some(id) = scope_id {
        return Ok(Some(id.to_string()));
    }
    let scope_name = match scope_name {
        Some(name) => name,
        None => return Ok(None),
    };
    let path = format!("/admin/realms/{}/client-scopes", realm);
    let payload = mcp
        .gateway
        .request_json(ctx, Method::GET, &path, Vec::new(), None)
        .await
        .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;
    let scopes: Vec<ClientScopeRepresentation> = match payload {
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|item| serde_json::from_value::<ClientScopeRepresentation>(item).ok())
            .collect(),
        _ => Vec::new(),
    };
    let found = scopes.into_iter().find(|scope| {
        scope
            .name
            .as_ref()
            .map(|name| name == scope_name)
            .unwrap_or(false)
    });
    Ok(found.and_then(|scope| scope.id))
}

fn set_config_list(
    config: &mut serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
    values: Vec<String>,
) {
    let target = keys
        .iter()
        .copied()
        .find(|key| config.contains_key(*key))
        .unwrap_or_else(|| keys[0]);
    let list = values.into_iter().map(serde_json::Value::String).collect();
    config.insert(target.to_string(), serde_json::Value::Array(list));
}

fn set_config_bool(
    config: &mut serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
    value: bool,
) {
    let as_text = if value { "true" } else { "false" };
    set_config_list(config, keys, vec![as_text.to_string()]);
}

fn resolve_registration_policy_provider_id(
    id: &Option<String>,
    name: &Option<String>,
    provider_id: &Option<String>,
) -> Option<String> {
    if id.is_none() && name.is_none() && provider_id.is_none() {
        Some(DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER.to_string())
    } else {
        provider_id.clone()
    }
}

fn match_registration_policy_components(
    components: &[serde_json::Value],
    id: Option<&str>,
    name: Option<&str>,
    provider_id: Option<&str>,
) -> Vec<usize> {
    if id.is_none() && name.is_none() && provider_id.is_none() {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for (idx, item) in components.iter().enumerate() {
        let item_id = item.get("id").and_then(|value| value.as_str());
        let item_name = item.get("name").and_then(|value| value.as_str());
        let item_provider = item.get("providerId").and_then(|value| value.as_str());

        let matches_all = id.map_or(true, |value| Some(value) == item_id)
            && name.map_or(true, |value| Some(value) == item_name)
            && provider_id.map_or(true, |value| Some(value) == item_provider);

        if matches_all {
            matches.push(idx);
        }
    }
    matches
}

fn registration_policy_config_values(
    config: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Vec<String> {
    let Some(value) = keys.iter().find_map(|key| config.get(*key)) else {
        return Vec::new();
    };
    match value {
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(|value| value.as_str().map(ToString::to_string))
            .collect(),
        serde_json::Value::String(value) => vec![value.clone()],
        _ => Vec::new(),
    }
}

fn registration_policy_config_bool(
    config: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<bool> {
    let value = keys.iter().find_map(|key| config.get(*key))?;
    match value {
        serde_json::Value::Bool(value) => Some(*value),
        serde_json::Value::String(value) => value.parse().ok(),
        serde_json::Value::Array(values) => values.first().and_then(|value| match value {
            serde_json::Value::Bool(value) => Some(*value),
            serde_json::Value::String(value) => value.parse().ok(),
            _ => None,
        }),
        _ => None,
    }
}

fn summarize_registration_policy_component(
    component: &serde_json::Value,
) -> Option<ClientRegistrationPolicySummary> {
    let object = component.as_object()?;
    let config = object
        .get("config")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    Some(ClientRegistrationPolicySummary {
        id: object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        name: object
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        provider_id: object
            .get("providerId")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        provider_type: object
            .get("providerType")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        parent_id: object
            .get("parentId")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        allowed_scopes: registration_policy_config_values(
            &config,
            &CONFIG_ALLOWED_CLIENT_SCOPES_KEYS,
        ),
        allow_default_scopes: registration_policy_config_bool(
            &config,
            &CONFIG_ALLOW_DEFAULT_SCOPES_KEYS,
        ),
        config: serde_json::Value::Object(config),
    })
}

#[cfg(test)]
mod tests {
    use axum::extract::Query;
    use axum::routing::{delete, get, post};
    use axum::Json;
    use serde_json::json;
    use std::collections::HashMap;

    use crate::test_support::{
        auth_context, build_config, build_server, parts_with_auth, TestServer,
        UNUSED_KEYCLOAK_BASE_URL,
    };

    async fn realms_handler() -> Json<serde_json::Value> {
        Json(json!([
            {"id": "realm-1", "realm": "alpha"},
            {"id": "realm-2", "realm": "beta"}
        ]))
    }

    async fn realm_default_scopes_handler() -> Json<serde_json::Value> {
        Json(json!([
            {"id": "scope-1", "name": "kc-admin-gateway-audience", "description": "Audience mapper", "protocol": "openid-connect"},
            {"id": "scope-2", "name": "roles", "description": "Role mapper", "protocol": "openid-connect"}
        ]))
    }

    async fn realm_get_handler() -> Json<serde_json::Value> {
        Json(json!({"id": "realm-1", "realm": "alpha"}))
    }

    async fn registration_policy_create_handler(
        Json(payload): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        assert_eq!(
            payload.get("providerType").and_then(|value| value.as_str()),
            Some(super::CLIENT_REG_POLICY_COMPONENT_TYPE)
        );
        assert_eq!(
            payload.get("providerId").and_then(|value| value.as_str()),
            Some(super::DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER)
        );
        assert_eq!(
            payload.get("name").and_then(|value| value.as_str()),
            Some(super::DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER)
        );
        assert_eq!(
            payload.get("parentId").and_then(|value| value.as_str()),
            Some("realm-1")
        );
        let config = payload
            .get("config")
            .and_then(|value| value.as_object())
            .expect("config object");
        assert_eq!(
            config.get("allowedClientScopes"),
            Some(&json!(["scope-a", "scope-b"]))
        );
        assert_eq!(config.get("allowDefaultScopes"), Some(&json!(["true"])));
        Json(json!({ "id": "component-1" }))
    }

    async fn registration_policy_components_handler(
        Query(params): Query<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        assert_eq!(
            params.get("type"),
            Some(&super::CLIENT_REG_POLICY_COMPONENT_TYPE.to_string())
        );
        Json(json!([
            {
                "id": "component-1",
                "name": "Allowed Client Scopes",
                "providerId": super::DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER,
                "providerType": super::CLIENT_REG_POLICY_COMPONENT_TYPE,
                "parentId": "realm-1",
                "config": {
                    "allowedClientScopes": ["scope-a", "scope-b"],
                    "allowDefaultScopes": ["false"],
                    "customOption": ["preserved"]
                }
            },
            {
                "id": "component-2",
                "name": "Other Policy",
                "providerId": "other-provider",
                "providerType": super::CLIENT_REG_POLICY_COMPONENT_TYPE,
                "parentId": "realm-1",
                "config": {
                    "allowed-client-scopes": "scope-c",
                    "allow-default-scopes": true
                }
            }
        ]))
    }

    async fn registration_policy_providers_handler() -> Json<serde_json::Value> {
        Json(json!([
            {
                "id": super::DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER,
                "helpText": "Restricts scopes available to dynamically registered clients."
            },
            {
                "id": "other-provider",
                "helpText": "Another registration policy provider."
            }
        ]))
    }

    async fn registration_policy_delete_handler() -> Json<serde_json::Value> {
        Json(json!({}))
    }

    #[test]
    fn registration_policy_match_requires_all_selectors() {
        let components = vec![
            json!({
                "id": "component-1",
                "name": "Allowed Client Scopes",
                "providerId": super::DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER,
            }),
            json!({
                "id": "component-2",
                "name": "Other Policy",
                "providerId": "other-provider",
            }),
        ];

        let matches = super::match_registration_policy_components(
            &components,
            Some("component-1"),
            None,
            Some("wrong-provider"),
        );
        assert!(matches.is_empty());

        let matches = super::match_registration_policy_components(
            &components,
            Some("component-1"),
            None,
            Some(super::DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER),
        );
        assert_eq!(matches, vec![0]);

        let matches = super::match_registration_policy_components(
            &components,
            None,
            Some("Other Policy"),
            None,
        );
        assert_eq!(matches, vec![1]);
    }

    #[tokio::test]
    async fn realms_list_returns_structured_output() {
        let router = axum::Router::new().route("/admin/realms", get(realms_handler));
        let server = TestServer::spawn(router).await;

        let config = build_config(
            server.base_url.clone(),
            UNUSED_KEYCLOAK_BASE_URL.to_string(),
        );
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.realms.read.clone());
        let parts = parts_with_auth(ctx);
        let result = mcp
            .realms_list(mcp_toolkit_core::rmcp::handler::server::tool::Extension(
                parts,
            ))
            .await
            .expect("realms list result");

        let structured = result.structured_content.expect("structured content");

        assert_eq!(
            structured,
            json!({
                "realms": [
                    {"id": "realm-1", "realm": "alpha"},
                    {"id": "realm-2", "realm": "beta"}
                ]
            })
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn realm_default_scopes_list_returns_structured_output() {
        let router = axum::Router::new().route(
            "/admin/realms/alpha/default-default-client-scopes",
            get(realm_default_scopes_handler),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(
            server.base_url.clone(),
            UNUSED_KEYCLOAK_BASE_URL.to_string(),
        );
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.realms.admin.clone());
        let parts = parts_with_auth(ctx);
        let args = super::RealmDefaultScopesListArgs {
            realm: "alpha".to_string(),
            kind: super::DefaultScopeKind::Default,
        };
        let result = mcp
            .realm_default_scopes_list(
                mcp_toolkit_core::rmcp::handler::server::wrapper::Parameters(args),
                mcp_toolkit_core::rmcp::handler::server::tool::Extension(parts),
            )
            .await
            .expect("default scopes list result");

        let structured = result.structured_content.expect("structured content");

        assert_eq!(
            structured,
            json!({
                "scopes": [
                    {"id": "scope-1", "name": "kc-admin-gateway-audience", "description": "Audience mapper", "protocol": "openid-connect"},
                    {"id": "scope-2", "name": "roles", "description": "Role mapper", "protocol": "openid-connect"}
                ]
            })
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn client_registration_policy_providers_list_returns_definitions() {
        let router = axum::Router::new().route(
            "/admin/realms/alpha/client-registration-policy/providers",
            get(registration_policy_providers_handler),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(
            server.base_url.clone(),
            UNUSED_KEYCLOAK_BASE_URL.to_string(),
        );
        let mcp = build_server(config);
        let ctx = auth_context(mcp.config.scope_map.realms.read.clone());
        let parts = parts_with_auth(ctx);
        let result = mcp
            .client_registration_policy_providers_list(
                mcp_toolkit_core::rmcp::handler::server::wrapper::Parameters(super::RealmArgs {
                    realm: "alpha".to_string(),
                }),
                mcp_toolkit_core::rmcp::handler::server::tool::Extension(parts),
            )
            .await
            .expect("client registration policy provider list result");

        assert_eq!(
            result.structured_content.expect("structured content"),
            json!({
                "providers": [
                    {
                        "id": super::DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER,
                        "help_text": "Restricts scopes available to dynamically registered clients."
                    },
                    {
                        "id": "other-provider",
                        "help_text": "Another registration policy provider."
                    }
                ]
            })
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn client_registration_policies_list_returns_configured_instances() {
        let router = axum::Router::new().route(
            "/admin/realms/alpha/components",
            get(registration_policy_components_handler),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(
            server.base_url.clone(),
            UNUSED_KEYCLOAK_BASE_URL.to_string(),
        );
        let mcp = build_server(config);
        let ctx = auth_context(mcp.config.scope_map.realms.read.clone());
        let parts = parts_with_auth(ctx);
        let args = super::ClientRegistrationPolicyListArgs {
            realm: "alpha".to_string(),
            id: None,
            name: None,
            provider_id: None,
        };
        let result = mcp
            .client_registration_policies_list(
                mcp_toolkit_core::rmcp::handler::server::wrapper::Parameters(args),
                mcp_toolkit_core::rmcp::handler::server::tool::Extension(parts),
            )
            .await
            .expect("configured client registration policy list result");

        assert_eq!(
            result.structured_content.expect("structured content"),
            json!({
                "policies": [
                    {
                        "id": "component-1",
                        "name": "Allowed Client Scopes",
                        "provider_id": super::DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER,
                        "provider_type": super::CLIENT_REG_POLICY_COMPONENT_TYPE,
                        "parent_id": "realm-1",
                        "allowed_scopes": ["scope-a", "scope-b"],
                        "allow_default_scopes": false,
                        "config": {
                            "allowedClientScopes": ["scope-a", "scope-b"],
                            "allowDefaultScopes": ["false"],
                            "customOption": ["preserved"]
                        }
                    },
                    {
                        "id": "component-2",
                        "name": "Other Policy",
                        "provider_id": "other-provider",
                        "provider_type": super::CLIENT_REG_POLICY_COMPONENT_TYPE,
                        "parent_id": "realm-1",
                        "allowed_scopes": ["scope-c"],
                        "allow_default_scopes": true,
                        "config": {
                            "allowed-client-scopes": "scope-c",
                            "allow-default-scopes": true
                        }
                    }
                ]
            })
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn client_registration_policies_get_defaults_to_allowed_scopes_provider() {
        let router = axum::Router::new().route(
            "/admin/realms/alpha/components",
            get(registration_policy_components_handler),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(
            server.base_url.clone(),
            UNUSED_KEYCLOAK_BASE_URL.to_string(),
        );
        let mcp = build_server(config);
        let ctx = auth_context(mcp.config.scope_map.realms.read.clone());
        let parts = parts_with_auth(ctx);
        let args = super::ClientRegistrationPolicyGetArgs {
            realm: "alpha".to_string(),
            id: None,
            name: None,
            provider_id: None,
        };
        let result = mcp
            .client_registration_policies_get(
                mcp_toolkit_core::rmcp::handler::server::wrapper::Parameters(args),
                mcp_toolkit_core::rmcp::handler::server::tool::Extension(parts),
            )
            .await
            .expect("configured client registration policy get result");

        assert_eq!(
            result.structured_content.expect("structured content"),
            json!({
                "policy": {
                    "id": "component-1",
                    "name": "Allowed Client Scopes",
                    "provider_id": super::DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER,
                    "provider_type": super::CLIENT_REG_POLICY_COMPONENT_TYPE,
                    "parent_id": "realm-1",
                    "allowed_scopes": ["scope-a", "scope-b"],
                    "allow_default_scopes": false,
                    "config": {
                        "allowedClientScopes": ["scope-a", "scope-b"],
                        "allowDefaultScopes": ["false"],
                        "customOption": ["preserved"]
                    }
                }
            })
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn client_registration_policies_create_returns_structured_output() {
        let router = axum::Router::new()
            .route("/admin/realms/alpha", get(realm_get_handler))
            .route(
                "/admin/realms/alpha/components",
                post(registration_policy_create_handler),
            );
        let server = TestServer::spawn(router).await;

        let config = build_config(
            server.base_url.clone(),
            UNUSED_KEYCLOAK_BASE_URL.to_string(),
        );
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.realms.write.clone());
        let parts = parts_with_auth(ctx);
        let args = super::ClientRegistrationPolicyCreateArgs {
            realm: "alpha".to_string(),
            name: None,
            provider_id: None,
            allowed_scopes: vec!["scope-a".to_string(), "scope-b".to_string()],
            allow_default_scopes: Some(true),
        };
        let result = mcp
            .client_registration_policies_create(
                mcp_toolkit_core::rmcp::handler::server::wrapper::Parameters(args),
                mcp_toolkit_core::rmcp::handler::server::tool::Extension(parts),
            )
            .await
            .expect("client registration policy create result");

        let structured = result.structured_content.expect("structured content");

        assert_eq!(
            structured,
            json!({
                "ok": true,
                "id": "component-1",
                "provider_id": super::DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER,
                "name": super::DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER,
                "allowed_scopes": ["scope-a", "scope-b"],
                "allow_default_scopes": true,
            })
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn client_registration_policies_delete_returns_structured_output() {
        let router = axum::Router::new()
            .route(
                "/admin/realms/alpha/components",
                get(registration_policy_components_handler),
            )
            .route(
                "/admin/realms/alpha/components/component-1",
                delete(registration_policy_delete_handler),
            );
        let server = TestServer::spawn(router).await;

        let config = build_config(
            server.base_url.clone(),
            UNUSED_KEYCLOAK_BASE_URL.to_string(),
        );
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.realms.write.clone());
        let parts = parts_with_auth(ctx);
        let args = super::ClientRegistrationPolicyDeleteArgs {
            realm: "alpha".to_string(),
            id: None,
            name: None,
            provider_id: None,
        };
        let result = mcp
            .client_registration_policies_delete(
                mcp_toolkit_core::rmcp::handler::server::wrapper::Parameters(args),
                mcp_toolkit_core::rmcp::handler::server::tool::Extension(parts),
            )
            .await
            .expect("client registration policy delete result");

        let structured = result.structured_content.expect("structured content");

        assert_eq!(
            structured,
            json!({
                "ok": true,
                "id": "component-1",
            })
        );

        server.shutdown();
    }
}
