//! # Clients Tools
//!
//! MCP tools for managing Keycloak clients, secrets, and protocol mappers.
//!
//! ## Rationale
//! Allows agents to automate client registration and configuration. It includes
//! specialized tools for bulk updates and pruning to manage large-scale deployments.
//!
//! ## Security Boundaries
//! * **Secret Access**: Gated by `keycloak-admin:clients:secrets`.
//! * **Confirmation**: Destructive or bulk actions require `confirm=true`.
//!
//! ## References
//! * **DESIGN**: `docs/design/admin-mcp-architecture.md`

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

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
use uuid::Uuid;

use crate::errors::{tool_error, tool_error_with_hint};
use crate::gateway::GatewayError;
use crate::server::KcAdminMcp;
use crate::tools::shared::{
    auth_from_parts, ensure_secret_tools_enabled, require_roles_for_scopes, require_scopes,
};
use crate::tools::validation::{validate_no_path_traversal, validate_realm_name, validate_uuid};

/// Arguments for `clients.list`.
/// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
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
pub struct ClientsListArgs {
    pub realm: String,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub max: Option<u32>,
}

/// Arguments for `clients.get`.
/// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
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
pub struct ClientsGetArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Arguments for `clients.search`.
/// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging raw tokens or secrets.
///
/// # Caveats
/// * `query` is matched case-insensitively using stable local ranking.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClientsSearchArgs {
    pub realm: String,
    pub query: String,
    #[serde(default)]
    pub exact: Option<bool>,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments for `clients.create`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes client configuration.
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
pub struct ClientsCreateArgs {
    pub realm: String,
    pub client_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub public_client: Option<bool>,
    #[serde(default)]
    pub service_accounts_enabled: Option<bool>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Arguments for `clients.update`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes client configuration.
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
pub struct ClientsUpdateArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub public_client: Option<bool>,
    #[serde(default)]
    pub service_accounts_enabled: Option<bool>,
    #[serde(default)]
    pub standard_flow_enabled: Option<bool>,
    #[serde(default)]
    pub direct_access_grants_enabled: Option<bool>,
    #[serde(default)]
    pub consent_required: Option<bool>,
    #[serde(default)]
    pub bearer_only: Option<bool>,
}

/// Arguments for `clients.delete`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive.
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
pub struct ClientsDeleteArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Arguments for `clients.enable` and `clients.disable`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes enablement state.
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
pub struct ClientsToggleArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Arguments for client scope list operations on a client.
/// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
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
pub struct ClientsScopesArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Arguments for adding or removing default/optional client scopes.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes client scope mappings.
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
pub struct ClientsScopesMutationArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub scope_ids: Option<Vec<String>>,
    #[serde(default)]
    pub scope_name: Option<String>,
    #[serde(default)]
    pub scope_names: Option<Vec<String>>,
    #[serde(default)]
    pub dry_run: Option<bool>,
}

/// Arguments for scope binding checks.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClientsScopeBindingArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    pub scope: String,
}

/// Arguments for scope ensure operations.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClientsScopeEnsureArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    pub scope: String,
    #[serde(default)]
    pub ensure: Option<bool>,
    #[serde(default)]
    pub dry_run: Option<bool>,
}

/// Arguments for replacing all default or optional client scopes.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive without `allow_empty`.
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
pub struct ClientsScopesReplaceArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub scope_ids: Option<Vec<String>>,
    #[serde(default)]
    pub scope_name: Option<String>,
    #[serde(default)]
    pub scope_names: Option<Vec<String>>,
    pub confirm: bool,
    #[serde(default)]
    pub dry_run: Option<bool>,
    #[serde(default)]
    pub allow_empty: Option<bool>,
}

/// Arguments for `clients.protocol_mappers.list`.
/// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
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
pub struct ClientsProtocolMapperListArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub include_config: Option<bool>,
}

/// Arguments for `clients.protocol_mappers.add`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes protocol mapper config.
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
pub struct ClientsProtocolMapperAddArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    pub name: String,
    pub protocol: String,
    pub protocol_mapper: String,
    #[serde(default)]
    pub config: Option<HashMap<String, String>>,
    #[serde(default)]
    pub consent_required: Option<bool>,
    #[serde(default)]
    pub consent_text: Option<String>,
}

/// Arguments for `clients.protocol_mappers.delete`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive.
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
pub struct ClientsProtocolMapperDeleteArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    pub mapper_id: String,
}

/// Arguments for `clients.redirect_uris.update`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes redirect URIs.
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
pub struct ClientsRedirectUrisArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    pub redirect_uris: Vec<String>,
}

/// Arguments for `clients.scope_mappings.realm.add` and `.delete`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes realm role mappings.
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
pub struct ClientsScopeMappingsRealmModifyArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub role_names: Option<Vec<String>>,
}

/// Arguments for `clients.scope_mappings.client`.
/// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
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
pub struct ClientsScopeMappingsClientArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub role_client_id: Option<String>,
    #[serde(default)]
    pub role_client_unique_id: Option<String>,
}

/// Arguments for `clients.scope_mappings.client.add` and `.delete`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes client role mappings.
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
pub struct ClientsScopeMappingsClientModifyArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub role_client_id: Option<String>,
    #[serde(default)]
    pub role_client_unique_id: Option<String>,
    #[serde(default)]
    pub role_names: Option<Vec<String>>,
}

/// Arguments for `clients.service_account.roles`.
/// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
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
pub struct ClientsServiceAccountArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Arguments for service-account realm role mutations.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes realm role mappings.
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
pub struct ClientsServiceAccountRealmArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub role_names: Option<Vec<String>>,
}

/// Arguments for service-account client role mutations.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes client role mappings.
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
pub struct ClientsServiceAccountClientArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub role_client_id: Option<String>,
    #[serde(default)]
    pub role_client_unique_id: Option<String>,
    #[serde(default)]
    pub role_names: Option<Vec<String>>,
}

/// Arguments for `clients.secrets.get`.
/// Required scopes: `keycloak-admin:clients:write` and `keycloak-admin:clients:secrets` (configurable); safety: exposes client secrets.
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
pub struct ClientsSecretArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Arguments for `clients.secrets.rotate`.
/// Required scopes: `keycloak-admin:clients:write` and `keycloak-admin:clients:secrets` (configurable); safety: rotates secrets.
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
pub struct ClientsSecretRotateArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    pub confirm: bool,
}

/// Arguments for `clients.introspection.create`.
/// Required scopes: `keycloak-admin:clients:write` and `keycloak-admin:clients:secrets` (configurable); safety: issues secrets.
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
pub struct ClientsIntrospectionCreateArgs {
    pub realm: String,
    pub client_id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub confirm: bool,
}

/// Per-client update payload for `clients.bulk_update`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes client configuration.
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
pub struct ClientsBulkUpdateItem {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub public_client: Option<bool>,
    #[serde(default)]
    pub service_accounts_enabled: Option<bool>,
    #[serde(default)]
    pub standard_flow_enabled: Option<bool>,
    #[serde(default)]
    pub direct_access_grants_enabled: Option<bool>,
    #[serde(default)]
    pub consent_required: Option<bool>,
    #[serde(default)]
    pub bearer_only: Option<bool>,
}

/// Arguments for `clients.bulk_update`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes multiple clients.
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
pub struct ClientsBulkUpdateArgs {
    pub realm: String,
    pub confirm: bool,
    #[serde(default)]
    pub dry_run: Option<bool>,
    pub updates: Vec<ClientsBulkUpdateItem>,
}

/// Prune action for `clients.prune`.
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
pub enum ClientsPruneAction {
    Disable,
    Delete,
}

/// Arguments for `clients.prune`.
/// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive unless `dry_run` is true.
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
pub struct ClientsPruneArgs {
    pub realm: String,
    pub confirm: bool,
    #[serde(default)]
    pub dry_run: Option<bool>,
    #[serde(default)]
    pub action: Option<ClientsPruneAction>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub client_id_prefix: Option<String>,
    #[serde(default)]
    pub client_id_pattern: Option<String>,
    #[serde(default)]
    pub exclude_client_ids: Option<Vec<String>>,
    #[serde(default)]
    pub max: Option<u32>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ClientRepresentation {
    id: Option<String>,
    #[serde(rename = "clientId")]
    client_id: Option<String>,
    name: Option<String>,
    enabled: Option<bool>,
    protocol: Option<String>,
    #[serde(rename = "publicClient")]
    public_client: Option<bool>,
    #[serde(rename = "createdTimestamp")]
    created_timestamp: Option<i64>,
    #[serde(rename = "serviceAccountsEnabled")]
    service_accounts_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ClientScopeRepresentation {
    id: Option<String>,
    name: Option<String>,
    protocol: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProtocolMapperRepresentation {
    id: Option<String>,
    name: Option<String>,
    protocol: Option<String>,
    #[serde(rename = "protocolMapper")]
    protocol_mapper: Option<String>,
    config: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct RoleRepresentation {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    composite: Option<bool>,
    #[serde(rename = "clientRole")]
    client_role: Option<bool>,
    #[serde(rename = "containerId")]
    container_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RoleMappings {
    #[serde(rename = "realmMappings")]
    realm_mappings: Option<Vec<RoleRepresentation>>,
    #[serde(rename = "clientMappings")]
    client_mappings: Option<HashMap<String, ClientRoleMappings>>,
}

#[derive(Debug, Deserialize)]
struct ClientRoleMappings {
    client: Option<String>,
    mappings: Option<Vec<RoleRepresentation>>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct ClientSummary {
    /// Backward-compatible Keycloak internal unique identifier field.
    id: Option<String>,
    /// Explicit alias for `id` so callers do not confuse it with `client_id`.
    keycloak_id: Option<String>,
    client_id: Option<String>,
    name: Option<String>,
    enabled: Option<bool>,
    protocol: Option<String>,
    created_at: Option<i64>,
    public_client: Option<bool>,
    service_accounts_enabled: Option<bool>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct ClientScopeSummary {
    id: Option<String>,
    name: Option<String>,
    protocol: Option<String>,
    description: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct ProtocolMapperSummary {
    id: Option<String>,
    name: Option<String>,
    protocol: Option<String>,
    protocol_mapper: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<HashMap<String, String>>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct RoleSummary {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    composite: Option<bool>,
    client_role: Option<bool>,
    container_id: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct ServiceAccountClientSummary {
    client_id: String,
    client_name: Option<String>,
    roles: Vec<RoleSummary>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct ServiceAccountRolesSummary {
    realm: Vec<RoleSummary>,
    clients: Vec<ServiceAccountClientSummary>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct BulkUpdateError {
    client: String,
    error: String,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct BulkUpdateSummary {
    updated: Vec<String>,
    skipped: Vec<String>,
    errors: Vec<BulkUpdateError>,
    dry_run: bool,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct PruneSummary {
    dry_run: bool,
    action: String,
    matched: Vec<String>,
    processed: Vec<String>,
    skipped: Vec<String>,
}

impl From<ClientRepresentation> for ClientSummary {
    fn from(value: ClientRepresentation) -> Self {
        let keycloak_id = value.id.clone();
        Self {
            id: value.id,
            keycloak_id,
            client_id: value.client_id,
            name: value.name,
            enabled: value.enabled,
            protocol: value.protocol,
            created_at: value.created_timestamp,
            public_client: value.public_client,
            service_accounts_enabled: value.service_accounts_enabled,
        }
    }
}

impl From<ClientScopeRepresentation> for ClientScopeSummary {
    fn from(value: ClientScopeRepresentation) -> Self {
        Self {
            id: value.id,
            name: value.name,
            protocol: value.protocol,
            description: value.description,
        }
    }
}

impl From<ProtocolMapperRepresentation> for ProtocolMapperSummary {
    fn from(value: ProtocolMapperRepresentation) -> Self {
        Self {
            id: value.id,
            name: value.name,
            protocol: value.protocol,
            protocol_mapper: value.protocol_mapper,
            config: value.config,
        }
    }
}

impl From<RoleRepresentation> for RoleSummary {
    fn from(value: RoleRepresentation) -> Self {
        Self {
            id: value.id,
            name: value.name,
            description: value.description,
            composite: value.composite,
            client_role: value.client_role,
            container_id: value.container_id,
        }
    }
}

mod core;
mod mappers;
mod roles;
mod scopes;
mod secrets;

impl KcAdminMcp {
    pub fn tool_router_clients() -> ToolRouter<KcAdminMcp> {
        Self::tool_router_clients_core()
            + Self::tool_router_clients_scopes()
            + Self::tool_router_clients_mappers()
            + Self::tool_router_clients_roles()
            + Self::tool_router_clients_secrets()
    }
}

enum ScopeKind {
    Default,
    Optional,
}

struct ScopeIdsResult {
    ids: Vec<String>,
    missing_names: Vec<String>,
}

struct ClientScopeLookup {
    by_id: HashMap<String, String>,
    by_name: HashMap<String, String>,
}

fn resolve_scope_lookup(scope_token: &str, lookup: &ClientScopeLookup) -> Option<String> {
    if let Ok(scope_id) = Uuid::parse_str(scope_token) {
        if let Some(scope_id) = lookup.by_id.get(&scope_id.to_string()) {
            return Some(scope_id.clone());
        }
    }
    lookup.by_name.get(scope_token).cloned()
}

async fn load_client_scope_lookup(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
) -> Result<ClientScopeLookup, crate::McpError> {
    let mut scopes: Vec<ClientScopeRepresentation> = Vec::new();
    let max = 100u32;
    let mut first = 0u32;

    loop {
        let payload = mcp
            .gateway
            .request_json(
                ctx,
                Method::GET,
                &format!("/admin/realms/{}/client-scopes", realm),
                vec![
                    ("first".to_string(), first.to_string()),
                    ("max".to_string(), max.to_string()),
                ],
                None,
            )
            .await
            .map_err(|err| match err {
                GatewayError::Upstream { status, summary } => crate::McpError::internal_error(
                    "gateway request failed",
                    Some(json!({
                        "upstream_status": status,
                        "upstream_error": summary,
                    })),
                ),
                _ => crate::McpError::internal_error("gateway request failed", None),
            })?;

        let page: Vec<ClientScopeRepresentation> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<ClientScopeRepresentation>(item).ok())
                .collect(),
            _ => Vec::new(),
        };

        let page_len = page.len();
        scopes.extend(page);
        if page_len < max as usize {
            break;
        }
        let next_first = first.saturating_add(max);
        if next_first <= first {
            return Err(crate::McpError::internal_error(
                "gateway request failed",
                Some(json!({
                    "upstream_error": "scope lookup pagination cursor did not advance",
                    "first": first,
                    "max": max,
                })),
            ));
        }
        first = next_first;
    }

    let mut by_id = HashMap::new();
    let mut by_name = HashMap::new();

    for scope in scopes {
        let id = match scope.id {
            Some(id) => id,
            None => continue,
        };
        let canonical_id = match Uuid::parse_str(&id) {
            Ok(scope_id) => scope_id.to_string(),
            Err(_) => id.clone(),
        };
        by_id.insert(canonical_id.clone(), id.clone());
        if let Some(name) = scope.name {
            by_name.entry(name).or_insert(id);
        }
    }

    Ok(ClientScopeLookup { by_id, by_name })
}

fn validate_client_lookup_input(
    id: Option<&String>,
    client_id: Option<&String>,
) -> Result<(), crate::McpError> {
    if let Some(id) = id {
        validate_uuid(id, "id")?;
    }
    if let Some(client_id) = client_id {
        validate_no_path_traversal(client_id, "client_id")?;
    }
    Ok(())
}

fn normalized_client_search_term(term: &str) -> String {
    term.to_ascii_lowercase().trim().to_string()
}

fn client_search_score(candidate: &ClientSummary, term: &str) -> u32 {
    if term.is_empty() {
        return 0;
    }
    let lowered_id = candidate
        .id
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let lowered_client_id = candidate
        .client_id
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let lowered_name = candidate
        .name
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let lowered_term = term.to_ascii_lowercase();

    if lowered_id == lowered_term {
        return 220;
    }
    if lowered_client_id == lowered_term {
        return 200;
    }
    if lowered_name == lowered_term {
        return 180;
    }
    if lowered_id.starts_with(&lowered_term) {
        return 160;
    }
    if lowered_id.contains(&lowered_term) {
        return 120;
    }
    if lowered_client_id.starts_with(&lowered_term) || lowered_name.starts_with(&lowered_term) {
        return 140;
    }
    if lowered_client_id.contains(&lowered_term) || lowered_name.contains(&lowered_term) {
        return 100;
    }
    0
}

fn rank_client_search_results(
    candidates: Vec<ClientSummary>,
    term: &str,
    limit: Option<u32>,
) -> Vec<ClientSummary> {
    let term = normalized_client_search_term(term);
    let mut ranked: Vec<(u32, ClientSummary)> = candidates
        .into_iter()
        .filter_map(|candidate| {
            let score = client_search_score(&candidate, &term);
            (score > 0).then_some((score, candidate))
        })
        .collect();

    ranked.sort_by(|(score_a, client_a), (score_b, client_b)| {
        score_b.cmp(score_a).then_with(|| {
            match (
                client_a
                    .client_id
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(client_b.client_id.as_deref().unwrap_or_default()),
                Ordering::Equal,
            ) {
                (Ordering::Equal, _) => client_a
                    .id
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(client_b.id.as_deref().unwrap_or_default()),
                (order, _) => order,
            }
        })
    });

    let limit = limit
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(100);
    ranked
        .into_iter()
        .take(limit)
        .map(|(_, candidate)| candidate)
        .collect()
}

async fn resolve_client_id(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    id: Option<&String>,
    client_id: Option<&String>,
) -> Result<Option<String>, crate::McpError> {
    validate_client_lookup_input(id, client_id)?;
    if let Some(id) = id {
        let canonical_id = Uuid::parse_str(id)
            .map(|id| id.to_string())
            .unwrap_or_else(|_| id.to_string());
        return Ok(Some(canonical_id));
    }
    let client_id = match client_id {
        Some(value) => value,
        None => return Ok(None),
    };
    let payload = mcp
        .gateway
        .request_json(
            ctx,
            Method::GET,
            &format!("/admin/realms/{}/clients", realm),
            vec![("clientId".to_string(), client_id.to_string())],
            None,
        )
        .await
        .map_err(|err| match err {
            GatewayError::Upstream { status, summary } => crate::McpError::internal_error(
                "gateway request failed",
                Some(json!({
                    "upstream_status": status,
                    "upstream_error": summary,
                })),
            ),
            _ => crate::McpError::internal_error("gateway request failed", None),
        })?;
    let clients: Vec<ClientRepresentation> = match payload {
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|item| serde_json::from_value::<ClientRepresentation>(item).ok())
            .collect(),
        _ => Vec::new(),
    };
    let mut matching_ids: Vec<String> = clients
        .into_iter()
        .filter(|client| {
            client
                .client_id
                .as_ref()
                .map(|value| value == client_id)
                .unwrap_or(false)
        })
        .filter_map(|client| client.id)
        .collect();
    matching_ids.sort_unstable();
    matching_ids.dedup();

    if matching_ids.len() > 1 {
        return Err(crate::McpError::internal_error(
            "ambiguous client_id lookup",
            Some(json!({
                "client_id": client_id,
                "matches": matching_ids,
                "hint": "Retry with id/keycloak_id to select the Keycloak internal unique identifier.",
            })),
        ));
    }

    Ok(matching_ids.into_iter().next())
}

async fn resolve_scope_ids(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    args: &ClientsScopesMutationArgs,
) -> Result<ScopeIdsResult, crate::McpError> {
    let lookup = load_client_scope_lookup(mcp, ctx, realm).await?;
    let mut ids = HashSet::new();
    let mut missing_names = Vec::new();
    if let Some(scope_id) = args.scope_id.as_ref() {
        match resolve_scope_lookup(scope_id, &lookup) {
            Some(id) => {
                ids.insert(id.to_string());
            }
            None => {
                missing_names.push(format!("scope_id:{scope_id}"));
            }
        }
    }
    if let Some(scope_ids) = args.scope_ids.as_ref() {
        for scope_id in scope_ids {
            match resolve_scope_lookup(scope_id, &lookup) {
                Some(id) => {
                    ids.insert(id.to_string());
                }
                None => {
                    missing_names.push(format!("scope_id:{scope_id}"));
                }
            }
        }
    }
    if let Some(scope_name) = args.scope_name.as_ref() {
        let resolved = resolve_scope_lookup(scope_name, &lookup);
        if let Some(id) = resolved {
            ids.insert(id);
        } else {
            missing_names.push(scope_name.to_string());
        }
    }
    if let Some(scope_names) = args.scope_names.as_ref() {
        for name in scope_names {
            let resolved = resolve_scope_lookup(name, &lookup);
            if let Some(id) = resolved {
                ids.insert(id);
            } else {
                missing_names.push(name.to_string());
            }
        }
    }
    let mut ids = ids.into_iter().collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    missing_names.sort_unstable();
    missing_names.dedup();
    Ok(ScopeIdsResult { ids, missing_names })
}

async fn resolve_client_scope_id(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    scope_id: Option<&String>,
    scope_name: Option<&String>,
) -> Result<Option<String>, crate::McpError> {
    let lookup = load_client_scope_lookup(mcp, ctx, realm).await?;
    let Some(scope_id) = scope_id else {
        return Ok(scope_name.and_then(|name| resolve_scope_lookup(name, &lookup)));
    };

    validate_no_path_traversal(scope_id, "scope_id")?;
    Ok(resolve_scope_lookup(scope_id, &lookup))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::routing::{get, put};
    use axum::Json;
    use serde_json::json;
    use std::collections::HashMap;

    use crate::test_support::{
        auth_context, build_config, build_server, parts_with_auth, TestServer,
    };

    async fn clients_list_handler(
        Query(params): Query<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        assert_eq!(params.get("clientId"), Some(&"client-1".to_string()));
        Json(json!([{ "id": "client-1-id", "clientId": "client-1" }]))
    }

    async fn toggle_handler(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
        assert!(payload.get("enabled").is_some());
        Json(json!({}))
    }

    #[tokio::test]
    async fn clients_enable_returns_structured_output() {
        let router = axum::Router::new()
            .route("/admin/realms/test/clients", get(clients_list_handler))
            .route(
                "/admin/realms/test/clients/client-1-id",
                put(toggle_handler),
            );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.clients.write.clone());
        let parts = parts_with_auth(ctx);
        let args = ClientsToggleArgs {
            realm: "test".to_string(),
            id: None,
            client_id: Some("client-1".to_string()),
        };

        let result = mcp
            .clients_enable(Parameters(args), Extension(parts))
            .await
            .expect("clients enable result");

        let structured = result.structured_content.expect("structured content");
        assert_eq!(
            structured,
            json!({
                "enabled": true,
                "id": "client-1-id"
            })
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn clients_disable_returns_structured_output() {
        let router = axum::Router::new()
            .route("/admin/realms/test/clients", get(clients_list_handler))
            .route(
                "/admin/realms/test/clients/client-1-id",
                put(toggle_handler),
            );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.clients.write.clone());
        let parts = parts_with_auth(ctx);
        let args = ClientsToggleArgs {
            realm: "test".to_string(),
            id: None,
            client_id: Some("client-1".to_string()),
        };

        let result = mcp
            .clients_disable(Parameters(args), Extension(parts))
            .await
            .expect("clients disable result");

        let structured = result.structured_content.expect("structured content");
        assert_eq!(
            structured,
            json!({
                "enabled": false,
                "id": "client-1-id"
            })
        );

        server.shutdown();
    }

    async fn clients_search_handler_uuid_false_positive(
        Query(params): Query<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let query = params
            .get("search")
            .expect("search query should be present")
            .as_str()
            .to_ascii_lowercase();
        assert_eq!(query, "123e4567-e89b-12d3-a456-426614174000");
        Json(json!([
            {
                "id": "123e4567-e89b-12d3-a456-426614174001",
                "clientId": format!("candidate-{query}"),
            },
            {
                "id": "123e4567-e89b-12d3-a456-426614174000-shadow",
                "clientId": "client-matches-id-fragment",
            },
        ]))
    }

    async fn clients_search_handler_by_uuid() -> Json<serde_json::Value> {
        Json(json!({
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "clientId": "exact-match"
        }))
    }

    async fn clients_search_handler_non_uuid() -> Json<serde_json::Value> {
        Json(json!([
            {
                "id": "client-alpha-id",
                "clientId": "alpha-service",
            },
            {
                "id": "client-beta-id",
                "clientId": "service-beta",
            },
        ]))
    }

    async fn clients_search_handler_exact_client_id(
        Query(params): Query<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        assert_eq!(params.get("clientId"), Some(&"agent-ops".to_string()));
        assert_eq!(params.get("search"), None);
        Json(json!([
            {
                "id": "agent-ops-internal-id",
                "clientId": "agent-ops",
            },
            {
                "id": "nearby-internal-id",
                "clientId": "agent-ops-dev",
            },
        ]))
    }

    #[tokio::test]
    async fn clients_search_uuid_query_filters_non_exact_hits() {
        let router = axum::Router::new()
            .route(
                "/admin/realms/test/clients/123e4567-e89b-12d3-a456-426614174000",
                get(clients_search_handler_by_uuid),
            )
            .route(
                "/admin/realms/test/clients",
                get(clients_search_handler_uuid_false_positive),
            );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);
        let ctx = auth_context(mcp.config.scope_map.clients.read.clone());
        let parts = parts_with_auth(ctx);
        let args = ClientsSearchArgs {
            realm: "test".to_string(),
            query: "123E4567-E89B-12D3-A456-426614174000".to_string(),
            exact: None,
            limit: Some(20),
        };

        let result = mcp
            .clients_search(Parameters(args), Extension(parts))
            .await
            .expect("clients search result");
        let structured = result.structured_content.expect("structured content");

        assert_eq!(
            structured["query"],
            json!("123E4567-E89B-12D3-A456-426614174000")
        );
        let results = structured
            .get("results")
            .and_then(|value| value.as_array())
            .expect("results array");
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]["id"],
            json!("123e4567-e89b-12d3-a456-426614174000")
        );
        assert_eq!(
            results[0]["keycloak_id"],
            json!("123e4567-e89b-12d3-a456-426614174000")
        );
        assert_eq!(results[0]["client_id"], json!("exact-match"));

        server.shutdown();
    }

    #[tokio::test]
    async fn clients_search_non_uuid_query_uses_fuzzy_search() {
        let router = axum::Router::new().route(
            "/admin/realms/test/clients",
            get(clients_search_handler_non_uuid),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);
        let ctx = auth_context(mcp.config.scope_map.clients.read.clone());
        let parts = parts_with_auth(ctx);
        let args = ClientsSearchArgs {
            realm: "test".to_string(),
            query: "service".to_string(),
            exact: None,
            limit: Some(10),
        };

        let result = mcp
            .clients_search(Parameters(args), Extension(parts))
            .await
            .expect("clients search result");
        let structured = result.structured_content.expect("structured content");
        let results = structured
            .get("results")
            .and_then(|value| value.as_array())
            .expect("results array");
        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0]["client_id"],
            serde_json::Value::String("service-beta".to_string())
        );
        assert_eq!(
            results[1]["client_id"],
            serde_json::Value::String("alpha-service".to_string())
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn clients_search_exact_client_id_uses_exact_lookup() {
        let router = axum::Router::new().route(
            "/admin/realms/test/clients",
            get(clients_search_handler_exact_client_id),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);
        let ctx = auth_context(mcp.config.scope_map.clients.read.clone());
        let parts = parts_with_auth(ctx);
        let args = ClientsSearchArgs {
            realm: "test".to_string(),
            query: "agent-ops".to_string(),
            exact: Some(true),
            limit: Some(10),
        };

        let result = mcp
            .clients_search(Parameters(args), Extension(parts))
            .await
            .expect("clients search result");
        let structured = result.structured_content.expect("structured content");
        let results = structured
            .get("results")
            .and_then(|value| value.as_array())
            .expect("results array");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["id"], json!("agent-ops-internal-id"));
        assert_eq!(results[0]["keycloak_id"], json!("agent-ops-internal-id"));
        assert_eq!(results[0]["client_id"], json!("agent-ops"));

        server.shutdown();
    }

    #[tokio::test]
    async fn clients_search_uuid_query_is_canonicalized_for_lookup() {
        let router = axum::Router::new()
            .route(
                "/admin/realms/test/clients/123e4567-e89b-12d3-a456-426614174000",
                get(clients_search_handler_by_uuid),
            )
            .route(
                "/admin/realms/test/clients",
                get(clients_search_handler_uuid_false_positive),
            );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);
        let ctx = auth_context(mcp.config.scope_map.clients.read.clone());
        let parts = parts_with_auth(ctx);
        let args = ClientsSearchArgs {
            realm: "test".to_string(),
            query: "123E4567-E89B-12D3-A456-426614174000".to_string(),
            exact: None,
            limit: Some(20),
        };

        let result = mcp
            .clients_search(Parameters(args), Extension(parts))
            .await
            .expect("clients search result");
        let structured = result.structured_content.expect("structured content");
        let results = structured
            .get("results")
            .and_then(|value| value.as_array())
            .expect("results array");
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]["id"],
            serde_json::Value::String("123e4567-e89b-12d3-a456-426614174000".to_string())
        );

        server.shutdown();
    }
}

async fn list_client_scopes(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    client_id: &str,
    kind: ScopeKind,
) -> Result<Vec<ClientScopeSummary>, crate::McpError> {
    let path = match kind {
        ScopeKind::Default => format!(
            "/admin/realms/{}/clients/{}/default-client-scopes",
            realm, client_id
        ),
        ScopeKind::Optional => format!(
            "/admin/realms/{}/clients/{}/optional-client-scopes",
            realm, client_id
        ),
    };
    let payload = mcp
        .gateway
        .request_json(ctx, Method::GET, &path, Vec::new(), None)
        .await
        .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;
    let scopes: Vec<ClientScopeSummary> = match payload {
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|item| serde_json::from_value::<ClientScopeRepresentation>(item).ok())
            .map(ClientScopeSummary::from)
            .collect(),
        _ => Vec::new(),
    };
    Ok(scopes)
}

async fn resolve_realm_roles(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    role_names: &[String],
) -> Result<ResolveRolesResult, crate::McpError> {
    let mut roles = Vec::new();
    let mut missing = Vec::new();
    for role_name in role_names.iter() {
        let path = format!("/admin/realms/{}/roles/{}", realm, role_name);
        let payload = mcp
            .gateway
            .request_json(ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;
        let role = serde_json::from_value::<RoleRepresentation>(payload).map_err(|_| {
            crate::McpError::internal_error("unexpected response from gateway", None)
        })?;
        if role.id.is_none() || role.name.is_none() {
            missing.push(role_name.to_string());
        } else {
            roles.push(role);
        }
    }
    Ok(ResolveRolesResult { roles, missing })
}

async fn resolve_client_roles(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    client_id: &str,
    role_names: &[String],
) -> Result<ResolveRolesResult, crate::McpError> {
    let mut roles = Vec::new();
    let mut missing = Vec::new();
    for role_name in role_names.iter() {
        let path = format!(
            "/admin/realms/{}/clients/{}/roles/{}",
            realm, client_id, role_name
        );
        let payload = mcp
            .gateway
            .request_json(ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;
        let role = serde_json::from_value::<RoleRepresentation>(payload).map_err(|_| {
            crate::McpError::internal_error("unexpected response from gateway", None)
        })?;
        if role.id.is_none() || role.name.is_none() {
            missing.push(role_name.to_string());
        } else {
            roles.push(role);
        }
    }
    Ok(ResolveRolesResult { roles, missing })
}

enum ServiceAccountLookup {
    Found(String),
    NotFound,
    NotEnabled { detail: Option<String> },
}

fn service_account_disabled_error(request_id: &str, detail: Option<&str>) -> CallToolResult {
    let message = match detail {
        Some(detail) if !detail.trim().is_empty() => {
            format!("Service accounts are not enabled for this client ({detail}).")
        }
        _ => "Service accounts are not enabled for this client.".to_string(),
    };
    tool_error_with_hint(
        "clients.service_account_disabled",
        &message,
        request_id,
        "Enable service accounts for the client or choose a client with service accounts enabled.",
    )
}

async fn resolve_service_account_user_id(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    id: Option<&String>,
    client_id: Option<&String>,
) -> Result<ServiceAccountLookup, crate::McpError> {
    let client_id = resolve_client_id(mcp, ctx, realm, id, client_id).await?;
    let client_id = match client_id {
        Some(id) => id,
        None => return Ok(ServiceAccountLookup::NotFound),
    };
    let path = format!(
        "/admin/realms/{}/clients/{}/service-account-user",
        realm, client_id
    );
    let payload = match mcp
        .gateway
        .request_json(ctx, Method::GET, &path, Vec::new(), None)
        .await
    {
        Ok(payload) => payload,
        Err(GatewayError::Upstream { status, summary }) => {
            if status == 404 {
                return Ok(ServiceAccountLookup::NotFound);
            }
            let summary_text = summary.as_deref().unwrap_or("");
            if status == 400 && summary_text.to_lowercase().contains("service account") {
                return Ok(ServiceAccountLookup::NotEnabled { detail: summary });
            }
            return Err(crate::McpError::internal_error(
                "gateway request failed",
                Some(json!({
                    "upstream_status": status,
                    "upstream_error": summary,
                })),
            ));
        }
        Err(_) => {
            return Err(crate::McpError::internal_error(
                "gateway request failed",
                None,
            ));
        }
    };
    Ok(match payload.get("id").and_then(|value| value.as_str()) {
        Some(id) if !id.trim().is_empty() => ServiceAccountLookup::Found(id.to_string()),
        _ => ServiceAccountLookup::NotFound,
    })
}

struct ResolveRolesResult {
    roles: Vec<RoleRepresentation>,
    missing: Vec<String>,
}
