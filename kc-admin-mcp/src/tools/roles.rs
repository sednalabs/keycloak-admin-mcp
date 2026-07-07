use axum::http::request::Parts;
use axum::http::Method;
use mcp_toolkit_core::rmcp::handler::server::tool::Extension;
use mcp_toolkit_core::rmcp::handler::server::wrapper::Parameters;
use mcp_toolkit_core::rmcp::model::CallToolResult;
use mcp_toolkit_core::rmcp::tool;
use mcp_toolkit_core::rmcp::tool_router;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::errors::tool_error;
use crate::server::KcAdminMcp;
use crate::tools::shared::{auth_from_parts, require_roles_for_scopes, require_scopes};

/// Arguments for `roles.list`.
/// Required scopes: `keycloak-admin:roles:read` (configurable); safety: read-only.
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
pub struct RolesListArgs {
    pub realm: String,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub max: Option<u32>,
}

/// Arguments for `roles.get` and `roles.list_composites`.
/// Required scopes: `keycloak-admin:roles:read` (configurable); safety: read-only.
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
pub struct RolesGetArgs {
    pub realm: String,
    pub name: String,
}

/// Arguments for `roles.create`.
/// Required scopes: `keycloak-admin:roles:write` (configurable); safety: writes role data.
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
pub struct RolesCreateArgs {
    pub realm: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub composite: Option<bool>,
}

/// Arguments for `roles.delete`.
/// Required scopes: `keycloak-admin:roles:write` (configurable); safety: destructive.
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
pub struct RolesDeleteArgs {
    pub realm: String,
    pub name: String,
}

/// Arguments for `roles.list_users`.
/// Required scopes: `keycloak-admin:roles:read` (configurable); safety: read-only.
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
pub struct RolesListUsersArgs {
    pub realm: String,
    pub name: String,
    #[serde(default)]
    pub first: Option<u32>,
    #[serde(default)]
    pub max: Option<u32>,
    #[serde(default)]
    pub brief_representation: Option<bool>,
}

/// Arguments for `roles.composites.add` and `roles.composites.remove`.
/// Required scopes: `keycloak-admin:roles:write` (configurable); safety: writes role composites.
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
pub struct RolesCompositeArgs {
    pub realm: String,
    pub name: String,
    #[serde(default)]
    pub role_names: Option<Vec<String>>,
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
struct RoleSummary {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    composite: Option<bool>,
    client_role: Option<bool>,
    container_id: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct RoleUserSummary {
    id: Option<String>,
    username: Option<String>,
    email: Option<String>,
    enabled: Option<bool>,
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

impl From<RoleUserRepresentation> for RoleUserSummary {
    fn from(value: RoleUserRepresentation) -> Self {
        Self {
            id: value.id,
            username: value.username,
            email: value.email,
            enabled: value.enabled,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RoleUserRepresentation {
    id: Option<String>,
    username: Option<String>,
    email: Option<String>,
    enabled: Option<bool>,
}

#[tool_router(router = tool_router_roles, vis = "pub")]
impl KcAdminMcp {
    /// List realm roles.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:roles:read` (configurable); safety: read-only.
    #[tool(name = "roles.list", description = "List realm roles.")]
    async fn roles_list(
        &self,
        Parameters(args): Parameters<RolesListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.roles.read;
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
        if let Some(max) = args.max {
            query.push(("max".to_string(), max.to_string()));
        }
        query.push(("briefRepresentation".to_string(), "true".to_string()));

        let path = format!("/admin/realms/{}/roles", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, query, None)
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

    /// Get a realm role by name.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:roles:read` (configurable); safety: read-only.
    #[tool(name = "roles.get", description = "Get a role by name.")]
    async fn roles_get(
        &self,
        Parameters(args): Parameters<RolesGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.roles.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!("/admin/realms/{}/roles/{}", args.realm, args.name);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let summary = serde_json::from_value::<RoleRepresentation>(payload)
            .map(RoleSummary::from)
            .map_err(|_| {
                crate::McpError::internal_error("unexpected response from gateway", None)
            })?;

        Ok(CallToolResult::structured(json!({ "role": summary })))
    }

    /// Create a new realm role.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:roles:write` (configurable); safety: writes role data.
    #[tool(name = "roles.create", description = "Create a new realm role.")]
    async fn roles_create(
        &self,
        Parameters(args): Parameters<RolesCreateArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.roles.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!("/admin/realms/{}/roles", args.realm);
        let body = json!({
            "name": args.name,
            "description": args.description,
            "composite": args.composite.unwrap_or(false),
        });
        let payload = self
            .gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let name = payload
            .as_object()
            .and_then(|obj| {
                obj.get("roleName")
                    .or_else(|| obj.get("name"))
                    .and_then(|value| value.as_str())
            })
            .unwrap_or(&args.name)
            .to_string();

        Ok(CallToolResult::structured(json!({ "name": name })))
    }

    /// Delete a realm role by name.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:roles:write` (configurable); safety: destructive.
    #[tool(name = "roles.delete", description = "Delete a realm role by name.")]
    async fn roles_delete(
        &self,
        Parameters(args): Parameters<RolesDeleteArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.roles.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!("/admin/realms/{}/roles/{}", args.realm, args.name);
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "deleted": true })))
    }

    /// List users assigned to a realm role.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:roles:read` (configurable); safety: read-only.
    #[tool(
        name = "roles.list_users",
        description = "List users assigned to a realm role."
    )]
    async fn roles_list_users(
        &self,
        Parameters(args): Parameters<RolesListUsersArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.roles.read;
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

        let path = format!("/admin/realms/{}/roles/{}/users", args.realm, args.name);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, query, None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let users: Vec<RoleUserSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<RoleUserRepresentation>(item).ok())
                .map(RoleUserSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "users": users })))
    }

    /// List composite roles for a realm role.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:roles:read` (configurable); safety: read-only.
    #[tool(
        name = "roles.list_composites",
        description = "List composite roles for a realm role."
    )]
    async fn roles_list_composites(
        &self,
        Parameters(args): Parameters<RolesGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.roles.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!(
            "/admin/realms/{}/roles/{}/composites",
            args.realm, args.name
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

    /// Add composite roles to a realm role.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:roles:write` (configurable); safety: writes role composites.
    #[tool(
        name = "roles.composites.add",
        description = "Add composite roles to a realm role."
    )]
    async fn roles_composites_add(
        &self,
        Parameters(args): Parameters<RolesCompositeArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.roles.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "roles.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }

        let mut resolved = Vec::new();
        for role_name in role_names.iter() {
            let path = format!("/admin/realms/{}/roles/{}", args.realm, role_name);
            let payload = self
                .gateway
                .request_json(&ctx, Method::GET, &path, Vec::new(), None)
                .await
                .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;
            let role = serde_json::from_value::<RoleRepresentation>(payload).map_err(|_| {
                crate::McpError::internal_error("unexpected response from gateway", None)
            })?;
            if role.id.is_none() || role.name.is_none() {
                return Ok(tool_error(
                    "roles.invalid_payload",
                    "Resolved role missing id or name.",
                    &ctx.request_id,
                ));
            }
            resolved.push(role);
        }

        let path = format!(
            "/admin/realms/{}/roles/{}/composites",
            args.realm, args.name
        );
        let body = serde_json::to_value(resolved)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Remove composite roles from a realm role.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:roles:write` (configurable); safety: writes role composites.
    #[tool(
        name = "roles.composites.remove",
        description = "Remove composite roles from a realm role."
    )]
    async fn roles_composites_remove(
        &self,
        Parameters(args): Parameters<RolesCompositeArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.roles.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "roles.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }

        let mut resolved = Vec::new();
        for role_name in role_names.iter() {
            let path = format!("/admin/realms/{}/roles/{}", args.realm, role_name);
            let payload = self
                .gateway
                .request_json(&ctx, Method::GET, &path, Vec::new(), None)
                .await
                .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;
            let role = serde_json::from_value::<RoleRepresentation>(payload).map_err(|_| {
                crate::McpError::internal_error("unexpected response from gateway", None)
            })?;
            if role.id.is_none() || role.name.is_none() {
                return Ok(tool_error(
                    "roles.invalid_payload",
                    "Resolved role missing id or name.",
                    &ctx.request_id,
                ));
            }
            resolved.push(role);
        }

        let path = format!(
            "/admin/realms/{}/roles/{}/composites",
            args.realm, args.name
        );
        let body = serde_json::to_value(resolved)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }
}
