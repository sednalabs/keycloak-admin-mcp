use std::collections::HashMap;

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

/// Arguments for `client_scopes.list`.
/// Required scopes: `keycloak-admin:client-scopes:read` (configurable); safety: read-only.
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
pub struct ClientScopesListArgs {
    pub realm: String,
}

/// Arguments for `client_scopes.get`.
/// Required scopes: `keycloak-admin:client-scopes:read` (configurable); safety: read-only.
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
pub struct ClientScopeGetArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Arguments for `client_scopes.create`.
/// Required scopes: `keycloak-admin:client-scopes:write` (configurable); safety: writes client scope data.
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
pub struct ClientScopeCreateArgs {
    pub realm: String,
    pub name: String,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Arguments for `client_scopes.delete`.
/// Required scopes: `keycloak-admin:client-scopes:write` (configurable); safety: destructive.
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
pub struct ClientScopeDeleteArgs {
    pub realm: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Arguments for client-scope scope-mapping reads.
/// Required scopes: `keycloak-admin:client-scopes:read` (configurable); safety: read-only.
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
pub struct ClientScopeRefArgs {
    pub realm: String,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub scope_name: Option<String>,
}

/// Arguments for `client_scopes.protocol_mappers.list`.
/// Required scopes: `keycloak-admin:client-scopes:read` (configurable); safety: read-only.
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
pub struct ClientScopeProtocolMapperListArgs {
    pub realm: String,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub scope_name: Option<String>,
    #[serde(default)]
    pub include_config: Option<bool>,
}

/// Arguments for `client_scopes.protocol_mappers.add`.
/// Required scopes: `keycloak-admin:client-scopes:write` (configurable); safety: writes protocol mapper config.
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
pub struct ClientScopeProtocolMapperAddArgs {
    pub realm: String,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub scope_name: Option<String>,
    pub mapper_name: String,
    pub protocol: String,
    pub protocol_mapper: String,
    #[serde(default)]
    pub config: Option<HashMap<String, String>>,
}

/// Arguments for `client_scopes.protocol_mappers.delete`.
/// Required scopes: `keycloak-admin:client-scopes:write` (configurable); safety: destructive.
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
pub struct ClientScopeProtocolMapperDeleteArgs {
    pub realm: String,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub scope_name: Option<String>,
    pub mapper_id: String,
}

/// Arguments for `client_scopes.scope_mappings.realm.add` and `.delete`.
/// Required scopes: `keycloak-admin:client-scopes:write` (configurable); safety: writes realm scope mappings.
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
pub struct ClientScopeScopeMappingsRealmModifyArgs {
    pub realm: String,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub scope_name: Option<String>,
    #[serde(default)]
    pub role_names: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ClientScopeRepresentation {
    id: Option<String>,
    name: Option<String>,
    protocol: Option<String>,
    description: Option<String>,
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

#[derive(Debug, Deserialize)]
struct ProtocolMapperRepresentation {
    id: Option<String>,
    name: Option<String>,
    protocol: Option<String>,
    #[serde(rename = "protocolMapper")]
    protocol_mapper: Option<String>,
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

#[tool_router(router = tool_router_client_scopes, vis = "pub")]
impl KcAdminMcp {
    /// List client scopes in a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:client-scopes:read` (configurable); safety: read-only.
    #[tool(
        name = "client_scopes.list",
        description = "List client scopes in a realm."
    )]
    async fn client_scopes_list(
        &self,
        Parameters(args): Parameters<ClientScopesListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.client_scopes.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!("/admin/realms/{}/client-scopes", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
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

        Ok(CallToolResult::structured(json!({ "scopes": scopes })))
    }

    /// Fetch a client scope by id or name.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:client-scopes:read` (configurable); safety: read-only.
    #[tool(
        name = "client_scopes.get",
        description = "Fetch a client scope by id or name."
    )]
    async fn client_scopes_get(
        &self,
        Parameters(args): Parameters<ClientScopeGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.client_scopes.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let scope_id = resolve_client_scope_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.name.as_ref(),
        )
        .await?;
        let scope_id = match scope_id {
            Some(id) => id,
            None => {
                return Ok(CallToolResult::structured(json!({
                    "scope": serde_json::Value::Null
                })))
            }
        };

        let path = format!("/admin/realms/{}/client-scopes/{}", args.realm, scope_id);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let summary = serde_json::from_value::<ClientScopeRepresentation>(payload)
            .map(ClientScopeSummary::from)
            .map_err(|_| {
                crate::McpError::internal_error("unexpected response from gateway", None)
            })?;

        Ok(CallToolResult::structured(json!({ "scope": summary })))
    }

    /// Create a client scope in a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:client-scopes:write` (configurable); safety: writes client scope data.
    #[tool(name = "client_scopes.create", description = "Create a client scope.")]
    async fn client_scopes_create(
        &self,
        Parameters(args): Parameters<ClientScopeCreateArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.client_scopes.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let body = json!({
            "name": args.name,
            "protocol": args.protocol.unwrap_or_else(|| "openid-connect".to_string()),
            "description": args.description,
        });
        let path = format!("/admin/realms/{}/client-scopes", args.realm);
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

    /// Delete a client scope by id or name.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:client-scopes:write` (configurable); safety: destructive.
    #[tool(
        name = "client_scopes.delete",
        description = "Delete a client scope by id or name."
    )]
    async fn client_scopes_delete(
        &self,
        Parameters(args): Parameters<ClientScopeDeleteArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.client_scopes.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let scope_id = resolve_client_scope_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.name.as_ref(),
        )
        .await?;
        let scope_id = match scope_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "client_scopes.not_found",
                    "Client scope not found.",
                    &ctx.request_id,
                ))
            }
        };

        let path = format!("/admin/realms/{}/client-scopes/{}", args.realm, scope_id);
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// List protocol mappers for a client scope.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:client-scopes:read` (configurable); safety: read-only.
    #[tool(
        name = "client_scopes.protocol_mappers.list",
        description = "List protocol mappers for a client scope."
    )]
    async fn client_scopes_protocol_mappers_list(
        &self,
        Parameters(args): Parameters<ClientScopeProtocolMapperListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.client_scopes.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let scope_id = resolve_client_scope_id(
            self,
            &ctx,
            &args.realm,
            args.scope_id.as_ref(),
            args.scope_name.as_ref(),
        )
        .await?;
        let scope_id = match scope_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "client_scopes.not_found",
                    "Client scope not found.",
                    &ctx.request_id,
                ))
            }
        };

        let path = format!(
            "/admin/realms/{}/client-scopes/{}/protocol-mappers/models",
            args.realm, scope_id
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let include_config = args.include_config.unwrap_or(false);
        let mappers: Vec<ProtocolMapperSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| {
                    serde_json::from_value::<ProtocolMapperRepresentation>(item).ok()
                })
                .map(|mapper| {
                    let mut summary = ProtocolMapperSummary::from(mapper);
                    if !include_config {
                        summary.config = None;
                    }
                    summary
                })
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "mappers": mappers })))
    }

    /// Add a protocol mapper to a client scope.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:client-scopes:write` (configurable); safety: writes mapper config.
    #[tool(
        name = "client_scopes.protocol_mappers.add",
        description = "Add a protocol mapper to a client scope."
    )]
    async fn client_scopes_protocol_mappers_add(
        &self,
        Parameters(args): Parameters<ClientScopeProtocolMapperAddArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.client_scopes.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let scope_id = resolve_client_scope_id(
            self,
            &ctx,
            &args.realm,
            args.scope_id.as_ref(),
            args.scope_name.as_ref(),
        )
        .await?;
        let scope_id = match scope_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "client_scopes.not_found",
                    "Client scope not found.",
                    &ctx.request_id,
                ))
            }
        };

        let path = format!(
            "/admin/realms/{}/client-scopes/{}/protocol-mappers/models",
            args.realm, scope_id
        );
        let body = json!({
            "name": args.mapper_name,
            "protocol": args.protocol,
            "protocolMapper": args.protocol_mapper,
            "config": args.config,
        });
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Delete a protocol mapper from a client scope.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:client-scopes:write` (configurable); safety: destructive.
    #[tool(
        name = "client_scopes.protocol_mappers.delete",
        description = "Delete a protocol mapper from a client scope."
    )]
    async fn client_scopes_protocol_mappers_delete(
        &self,
        Parameters(args): Parameters<ClientScopeProtocolMapperDeleteArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.client_scopes.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let scope_id = resolve_client_scope_id(
            self,
            &ctx,
            &args.realm,
            args.scope_id.as_ref(),
            args.scope_name.as_ref(),
        )
        .await?;
        let scope_id = match scope_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "client_scopes.not_found",
                    "Client scope not found.",
                    &ctx.request_id,
                ))
            }
        };

        let path = format!(
            "/admin/realms/{}/client-scopes/{}/protocol-mappers/models/{}",
            args.realm, scope_id, args.mapper_id
        );
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// List realm scope mappings for a client scope.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:client-scopes:read` (configurable); safety: read-only.
    #[tool(
        name = "client_scopes.scope_mappings.realm",
        description = "List realm scope mappings for a client scope."
    )]
    async fn client_scopes_scope_mappings_realm(
        &self,
        Parameters(args): Parameters<ClientScopeRefArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.client_scopes.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let scope_id = resolve_client_scope_id(
            self,
            &ctx,
            &args.realm,
            args.scope_id.as_ref(),
            args.scope_name.as_ref(),
        )
        .await?;
        let scope_id = match scope_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "client_scopes.not_found",
                    "Client scope not found.",
                    &ctx.request_id,
                ))
            }
        };

        let path = format!(
            "/admin/realms/{}/client-scopes/{}/scope-mappings/realm",
            args.realm, scope_id
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

    /// Add realm scope mappings to a client scope.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:client-scopes:write` (configurable); safety: writes scope mappings.
    #[tool(
        name = "client_scopes.scope_mappings.realm.add",
        description = "Add realm scope mappings to a client scope."
    )]
    async fn client_scopes_scope_mappings_realm_add(
        &self,
        Parameters(args): Parameters<ClientScopeScopeMappingsRealmModifyArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.client_scopes.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "client_scopes.invalid_input",
                "role_names must include at least one role name.",
                &ctx.request_id,
            ));
        }
        let scope_id = resolve_client_scope_id(
            self,
            &ctx,
            &args.realm,
            args.scope_id.as_ref(),
            args.scope_name.as_ref(),
        )
        .await?;
        let scope_id = match scope_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "client_scopes.not_found",
                    "Client scope not found.",
                    &ctx.request_id,
                ))
            }
        };

        let resolved = resolve_realm_roles(self, &ctx, &args.realm, &role_names).await?;
        if resolved.missing.len() > 0 {
            return Ok(tool_error(
                "client_scopes.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/client-scopes/{}/scope-mappings/realm",
            args.realm, scope_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Remove realm scope mappings from a client scope.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:client-scopes:write` (configurable); safety: destructive.
    #[tool(
        name = "client_scopes.scope_mappings.realm.delete",
        description = "Remove realm scope mappings from a client scope."
    )]
    async fn client_scopes_scope_mappings_realm_delete(
        &self,
        Parameters(args): Parameters<ClientScopeScopeMappingsRealmModifyArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.client_scopes.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "client_scopes.invalid_input",
                "role_names must include at least one role name.",
                &ctx.request_id,
            ));
        }
        let scope_id = resolve_client_scope_id(
            self,
            &ctx,
            &args.realm,
            args.scope_id.as_ref(),
            args.scope_name.as_ref(),
        )
        .await?;
        let scope_id = match scope_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "client_scopes.not_found",
                    "Client scope not found.",
                    &ctx.request_id,
                ))
            }
        };

        let resolved = resolve_realm_roles(self, &ctx, &args.realm, &role_names).await?;
        if resolved.missing.len() > 0 {
            return Ok(tool_error(
                "client_scopes.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/client-scopes/{}/scope-mappings/realm",
            args.realm, scope_id
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
