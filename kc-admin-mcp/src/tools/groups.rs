use axum::http::request::Parts;
use axum::http::Method;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::tool;
use rmcp::tool_router;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::errors::tool_error;
use crate::server::KcAdminMcp;
use crate::tools::shared::{auth_from_parts, require_roles_for_scopes, require_scopes};

/// Arguments for `groups.list`.
/// Required scopes: `keycloak-admin:groups:read` (configurable); safety: read-only.
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
pub struct GroupsListArgs {
    pub realm: String,
    #[serde(default)]
    pub search: Option<String>,
}

/// Arguments for `groups.get` and other group read tools.
/// Required scopes: `keycloak-admin:groups:read` (configurable); safety: read-only.
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
pub struct GroupsGetArgs {
    pub realm: String,
    pub group_id: String,
}

/// Arguments for `groups.create`.
/// Required scopes: `keycloak-admin:groups:write` (configurable); safety: writes group data.
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
pub struct GroupsCreateArgs {
    pub realm: String,
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
}

/// Arguments for `groups.members.list`.
/// Required scopes: `keycloak-admin:groups:read` (configurable); safety: read-only.
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
pub struct GroupsMembersListArgs {
    pub realm: String,
    pub group_id: String,
    #[serde(default)]
    pub first: Option<u32>,
    #[serde(default)]
    pub max: Option<u32>,
    #[serde(default)]
    pub brief_representation: Option<bool>,
}

/// Arguments for `groups.delete`.
/// Required scopes: `keycloak-admin:groups:write` (configurable); safety: destructive.
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
pub struct GroupsDeleteArgs {
    pub realm: String,
    pub group_id: String,
}

/// Arguments for `groups.roles.realm.add` and `groups.roles.realm.remove`.
/// Required scopes: `keycloak-admin:groups:write` (configurable); safety: writes realm role mappings.
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
pub struct GroupRolesRealmArgs {
    pub realm: String,
    pub group_id: String,
    #[serde(default)]
    pub role_names: Option<Vec<String>>,
}

/// Arguments for `groups.roles.clients`.
/// Required scopes: `keycloak-admin:groups:read` (configurable); safety: read-only.
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
pub struct GroupRolesClientArgs {
    pub realm: String,
    pub group_id: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_unique_id: Option<String>,
}

/// Arguments for `groups.roles.client.add` and `groups.roles.client.remove`.
/// Required scopes: `keycloak-admin:groups:write` (configurable); safety: writes client role mappings.
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
pub struct GroupRolesClientModifyArgs {
    pub realm: String,
    pub group_id: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_unique_id: Option<String>,
    #[serde(default)]
    pub role_names: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct GroupRepresentation {
    id: Option<String>,
    name: Option<String>,
    path: Option<String>,
    #[serde(rename = "parentId")]
    parent_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MemberRepresentation {
    id: Option<String>,
    username: Option<String>,
    email: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ClientRepresentation {
    id: Option<String>,
    #[serde(rename = "clientId")]
    client_id: Option<String>,
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

#[derive(Debug, serde::Serialize, JsonSchema)]
struct GroupSummary {
    id: Option<String>,
    name: Option<String>,
    path: Option<String>,
    parent_id: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct MemberSummary {
    id: Option<String>,
    username: Option<String>,
    email: Option<String>,
    enabled: Option<bool>,
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

impl From<GroupRepresentation> for GroupSummary {
    fn from(value: GroupRepresentation) -> Self {
        Self {
            id: value.id,
            name: value.name,
            path: value.path,
            parent_id: value.parent_id,
        }
    }
}

impl From<MemberRepresentation> for MemberSummary {
    fn from(value: MemberRepresentation) -> Self {
        Self {
            id: value.id,
            username: value.username,
            email: value.email,
            enabled: value.enabled,
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

#[tool_router(router = tool_router_groups, vis = "pub")]
impl KcAdminMcp {
    /// List groups within a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:groups:read` (configurable); safety: read-only.
    #[tool(name = "groups.list", description = "List groups within a realm.")]
    async fn groups_list(
        &self,
        Parameters(args): Parameters<GroupsListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.groups.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let mut query = Vec::new();
        if let Some(search) = args.search {
            query.push(("search".to_string(), search));
        }

        let path = format!("/admin/realms/{}/groups", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, query, None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let groups: Vec<GroupSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<GroupRepresentation>(item).ok())
                .map(GroupSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "groups": groups })))
    }

    /// Get a group by id.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:groups:read` (configurable); safety: read-only.
    #[tool(name = "groups.get", description = "Get a group by id.")]
    async fn groups_get(
        &self,
        Parameters(args): Parameters<GroupsGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.groups.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!("/admin/realms/{}/groups/{}", args.realm, args.group_id);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let summary = serde_json::from_value::<GroupRepresentation>(payload)
            .map(GroupSummary::from)
            .map_err(|_| {
                crate::McpError::internal_error("unexpected response from gateway", None)
            })?;

        Ok(CallToolResult::structured(json!({ "group": summary })))
    }

    /// Create a group in a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:groups:write` (configurable); safety: writes group data.
    #[tool(name = "groups.create", description = "Create a group in a realm.")]
    async fn groups_create(
        &self,
        Parameters(args): Parameters<GroupsCreateArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.groups.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = if let Some(parent_id) = args.parent_id.as_ref() {
            format!("/admin/realms/{}/groups/{}/children", args.realm, parent_id)
        } else {
            format!("/admin/realms/{}/groups", args.realm)
        };

        let body = json!({ "name": args.name });
        let payload = self
            .gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let id = payload
            .as_object()
            .and_then(|obj| obj.get("id"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        Ok(CallToolResult::structured(json!({ "id": id })))
    }

    /// List members of a group.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:groups:read` (configurable); safety: read-only.
    #[tool(name = "groups.members.list", description = "List members of a group.")]
    async fn groups_members_list(
        &self,
        Parameters(args): Parameters<GroupsMembersListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.groups.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let mut query = Vec::new();
        if let Some(first) = args.first {
            query.push(("first".to_string(), first.to_string()));
        }
        if let Some(max) = args.max {
            query.push(("max".to_string(), max.to_string()));
        }
        if let Some(brief) = args.brief_representation {
            query.push(("briefRepresentation".to_string(), brief.to_string()));
        }

        let path = format!(
            "/admin/realms/{}/groups/{}/members",
            args.realm, args.group_id
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, query, None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let members: Vec<MemberSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<MemberRepresentation>(item).ok())
                .map(MemberSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "members": members })))
    }

    /// Delete a group by id.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:groups:write` (configurable); safety: destructive.
    #[tool(name = "groups.delete", description = "Delete a group by id.")]
    async fn groups_delete(
        &self,
        Parameters(args): Parameters<GroupsDeleteArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.groups.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!("/admin/realms/{}/groups/{}", args.realm, args.group_id);
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "deleted": true })))
    }

    /// List realm role mappings for a group.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:groups:read` (configurable); safety: read-only.
    #[tool(
        name = "groups.roles.realm",
        description = "List realm role mappings for a group."
    )]
    async fn groups_roles_realm(
        &self,
        Parameters(args): Parameters<GroupsGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.groups.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!(
            "/admin/realms/{}/groups/{}/role-mappings/realm",
            args.realm, args.group_id
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let roles: Vec<RoleSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<RoleRepresentation>(item).ok())
                .map(RoleSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "roles": roles })))
    }

    /// List client role mappings for a group.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:groups:read` (configurable); safety: read-only.
    #[tool(
        name = "groups.roles.clients",
        description = "List client role mappings for a group."
    )]
    async fn groups_roles_clients(
        &self,
        Parameters(args): Parameters<GroupRolesClientArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.groups.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let client_unique_id = match resolve_client_unique_id(
            self,
            &ctx,
            &args.realm,
            args.client_unique_id.as_ref(),
            args.client_id.as_ref(),
        )
        .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                return Ok(tool_error(
                    "groups.client_not_found",
                    "Client not found.",
                    &ctx.request_id,
                ))
            }
            Err(err) => return Err(err),
        };

        let path = format!(
            "/admin/realms/{}/groups/{}/role-mappings/clients/{}",
            args.realm, args.group_id, client_unique_id
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let roles: Vec<RoleSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<RoleRepresentation>(item).ok())
                .map(RoleSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "roles": roles })))
    }

    /// Add realm roles to a group.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:groups:write` (configurable); safety: writes role mappings.
    #[tool(
        name = "groups.roles.realm.add",
        description = "Add realm roles to a group."
    )]
    async fn groups_roles_realm_add(
        &self,
        Parameters(args): Parameters<GroupRolesRealmArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.groups.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "groups.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }
        let resolved = resolve_realm_roles(self, &ctx, &args.realm, &role_names).await?;
        if resolved.missing.len() > 0 {
            return Ok(tool_error(
                "groups.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/groups/{}/role-mappings/realm",
            args.realm, args.group_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Remove realm roles from a group.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:groups:write` (configurable); safety: writes role mappings.
    #[tool(
        name = "groups.roles.realm.remove",
        description = "Remove realm roles from a group."
    )]
    async fn groups_roles_realm_remove(
        &self,
        Parameters(args): Parameters<GroupRolesRealmArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.groups.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "groups.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }
        let resolved = resolve_realm_roles(self, &ctx, &args.realm, &role_names).await?;
        if resolved.missing.len() > 0 {
            return Ok(tool_error(
                "groups.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/groups/{}/role-mappings/realm",
            args.realm, args.group_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Add client roles to a group.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:groups:write` (configurable); safety: writes role mappings.
    #[tool(
        name = "groups.roles.client.add",
        description = "Add client roles to a group."
    )]
    async fn groups_roles_client_add(
        &self,
        Parameters(args): Parameters<GroupRolesClientModifyArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.groups.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "groups.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }

        let client_unique_id = match resolve_client_unique_id(
            self,
            &ctx,
            &args.realm,
            args.client_unique_id.as_ref(),
            args.client_id.as_ref(),
        )
        .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                return Ok(tool_error(
                    "groups.client_not_found",
                    "Client not found.",
                    &ctx.request_id,
                ))
            }
            Err(err) => return Err(err),
        };

        let resolved =
            resolve_client_roles(self, &ctx, &args.realm, &client_unique_id, &role_names).await?;
        if resolved.missing.len() > 0 {
            return Ok(tool_error(
                "groups.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/groups/{}/role-mappings/clients/{}",
            args.realm, args.group_id, client_unique_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Remove client roles from a group.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:groups:write` (configurable); safety: writes role mappings.
    #[tool(
        name = "groups.roles.client.remove",
        description = "Remove client roles from a group."
    )]
    async fn groups_roles_client_remove(
        &self,
        Parameters(args): Parameters<GroupRolesClientModifyArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.groups.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "groups.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }

        let client_unique_id = match resolve_client_unique_id(
            self,
            &ctx,
            &args.realm,
            args.client_unique_id.as_ref(),
            args.client_id.as_ref(),
        )
        .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                return Ok(tool_error(
                    "groups.client_not_found",
                    "Client not found.",
                    &ctx.request_id,
                ))
            }
            Err(err) => return Err(err),
        };

        let resolved =
            resolve_client_roles(self, &ctx, &args.realm, &client_unique_id, &role_names).await?;
        if resolved.missing.len() > 0 {
            return Ok(tool_error(
                "groups.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/groups/{}/role-mappings/clients/{}",
            args.realm, args.group_id, client_unique_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }
}

struct ResolveRolesResult {
    roles: Vec<RoleRepresentation>,
    missing: Vec<String>,
}

async fn resolve_client_unique_id(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    client_unique_id: Option<&String>,
    client_id: Option<&String>,
) -> Result<Option<String>, crate::McpError> {
    if let Some(unique_id) = client_unique_id {
        return Ok(Some(unique_id.to_string()));
    }
    let client_id = match client_id {
        Some(value) => value,
        None => return Ok(None),
    };
    let path = format!("/admin/realms/{}/clients", realm);
    let payload = mcp
        .gateway
        .request_json(
            ctx,
            Method::GET,
            &path,
            vec![("clientId".to_string(), client_id.to_string())],
            None,
        )
        .await
        .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;
    let clients: Vec<ClientRepresentation> = match payload {
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|item| serde_json::from_value::<ClientRepresentation>(item).ok())
            .collect(),
        _ => Vec::new(),
    };
    let found = clients.into_iter().find(|client| {
        client
            .client_id
            .as_ref()
            .map(|id| id == client_id)
            .unwrap_or(false)
    });
    Ok(found.and_then(|client| client.id))
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
    client_unique_id: &str,
    role_names: &[String],
) -> Result<ResolveRolesResult, crate::McpError> {
    let mut roles = Vec::new();
    let mut missing = Vec::new();
    for role_name in role_names.iter() {
        let path = format!(
            "/admin/realms/{}/clients/{}/roles/{}",
            realm, client_unique_id, role_name
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
