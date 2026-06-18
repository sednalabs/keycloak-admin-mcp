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

use crate::server::KcAdminMcp;
use crate::tools::shared::{auth_from_parts, require_roles_for_scopes, require_scopes};

/// Arguments for `idp.list`.
/// Required scopes: `keycloak-admin:idp:read` (configurable); safety: read-only.
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
pub struct IdentityProvidersListArgs {
    pub realm: String,
}

/// Arguments for `idp.get`.
/// Required scopes: `keycloak-admin:idp:read` (configurable); safety: read-only.
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
pub struct IdentityProviderGetArgs {
    pub realm: String,
    pub alias: String,
}

/// Arguments for `idp.create`.
/// Required scopes: `keycloak-admin:idp:write` (configurable); safety: writes identity provider configuration.
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
pub struct IdentityProviderCreateArgs {
    pub realm: String,
    pub alias: String,
    pub provider_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub config: Option<HashMap<String, String>>,
}

/// Arguments for `idp.delete`.
/// Required scopes: `keycloak-admin:idp:write` (configurable); safety: destructive.
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
pub struct IdentityProviderDeleteArgs {
    pub realm: String,
    pub alias: String,
}

/// Arguments for `idp.mappers.list`.
/// Required scopes: `keycloak-admin:idp:read` (configurable); safety: read-only.
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
pub struct IdentityProviderMappersListArgs {
    pub realm: String,
    pub alias: String,
}

/// Arguments for `idp.mappers.add`.
/// Required scopes: `keycloak-admin:idp:write` (configurable); safety: writes mapper configuration.
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
pub struct IdentityProviderMapperCreateArgs {
    pub realm: String,
    pub alias: String,
    pub name: String,
    pub identity_provider_mapper: String,
    #[serde(default)]
    pub config: Option<HashMap<String, String>>,
}

/// Arguments for `idp.mappers.delete`.
/// Required scopes: `keycloak-admin:idp:write` (configurable); safety: destructive.
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
pub struct IdentityProviderMapperDeleteArgs {
    pub realm: String,
    pub alias: String,
    pub mapper_id: String,
}

#[derive(Debug, Deserialize)]
struct IdentityProviderRepresentation {
    alias: Option<String>,
    #[serde(rename = "providerId")]
    provider_id: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct IdentityProviderMapperRepresentation {
    id: Option<String>,
    name: Option<String>,
    #[serde(rename = "identityProviderAlias")]
    identity_provider_alias: Option<String>,
    #[serde(rename = "identityProviderMapper")]
    identity_provider_mapper: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct IdentityProviderSummary {
    alias: Option<String>,
    provider_id: Option<String>,
    display_name: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct IdentityProviderMapperSummary {
    id: Option<String>,
    name: Option<String>,
    identity_provider_alias: Option<String>,
    identity_provider_mapper: Option<String>,
}

impl From<IdentityProviderRepresentation> for IdentityProviderSummary {
    fn from(value: IdentityProviderRepresentation) -> Self {
        Self {
            alias: value.alias,
            provider_id: value.provider_id,
            display_name: value.display_name,
            enabled: value.enabled,
        }
    }
}

impl From<IdentityProviderMapperRepresentation> for IdentityProviderMapperSummary {
    fn from(value: IdentityProviderMapperRepresentation) -> Self {
        Self {
            id: value.id,
            name: value.name,
            identity_provider_alias: value.identity_provider_alias,
            identity_provider_mapper: value.identity_provider_mapper,
        }
    }
}

#[tool_router(router = tool_router_identity_providers, vis = "pub")]
impl KcAdminMcp {
    /// List identity providers in a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:idp:read` (configurable); safety: read-only.
    #[tool(name = "idp.list", description = "List identity providers in a realm.")]
    async fn identity_providers_list(
        &self,
        Parameters(args): Parameters<IdentityProvidersListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.identity_providers.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!("/admin/realms/{}/identity-provider/instances", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let providers: Vec<IdentityProviderSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| {
                    serde_json::from_value::<IdentityProviderRepresentation>(item).ok()
                })
                .map(IdentityProviderSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(
            json!({ "providers": providers }),
        ))
    }

    /// Fetch an identity provider by alias.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:idp:read` (configurable); safety: read-only.
    #[tool(name = "idp.get", description = "Fetch an identity provider by alias.")]
    async fn identity_providers_get(
        &self,
        Parameters(args): Parameters<IdentityProviderGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.identity_providers.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!(
            "/admin/realms/{}/identity-provider/instances/{}",
            args.realm, args.alias
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let provider = serde_json::from_value::<IdentityProviderRepresentation>(payload)
            .map(IdentityProviderSummary::from)
            .map_err(|_| {
                crate::McpError::internal_error("unexpected response from gateway", None)
            })?;

        Ok(CallToolResult::structured(json!({ "provider": provider })))
    }

    /// Create an identity provider in a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:idp:write` (configurable); safety: writes IdP configuration.
    #[tool(
        name = "idp.create",
        description = "Create an identity provider in a realm."
    )]
    async fn identity_providers_create(
        &self,
        Parameters(args): Parameters<IdentityProviderCreateArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.identity_providers.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let body = json!({
            "alias": args.alias,
            "providerId": args.provider_id,
            "displayName": args.display_name,
            "enabled": args.enabled.unwrap_or(true),
            "config": args.config,
        });
        let path = format!("/admin/realms/{}/identity-provider/instances", args.realm);
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

    /// Delete an identity provider by alias.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:idp:write` (configurable); safety: destructive.
    #[tool(
        name = "idp.delete",
        description = "Delete an identity provider by alias."
    )]
    async fn identity_providers_delete(
        &self,
        Parameters(args): Parameters<IdentityProviderDeleteArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.identity_providers.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!(
            "/admin/realms/{}/identity-provider/instances/{}",
            args.realm, args.alias
        );
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// List identity provider mappers by alias.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:idp:read` (configurable); safety: read-only.
    #[tool(
        name = "idp.mappers.list",
        description = "List identity provider mappers by alias."
    )]
    async fn identity_provider_mappers_list(
        &self,
        Parameters(args): Parameters<IdentityProviderMappersListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.identity_providers.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!(
            "/admin/realms/{}/identity-provider/instances/{}/mappers",
            args.realm, args.alias
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let mappers: Vec<IdentityProviderMapperSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| {
                    serde_json::from_value::<IdentityProviderMapperRepresentation>(item).ok()
                })
                .map(IdentityProviderMapperSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "mappers": mappers })))
    }

    /// Add a mapper to an identity provider.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:idp:write` (configurable); safety: writes mapper configuration.
    #[tool(
        name = "idp.mappers.add",
        description = "Add a mapper to an identity provider."
    )]
    async fn identity_provider_mappers_add(
        &self,
        Parameters(args): Parameters<IdentityProviderMapperCreateArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.identity_providers.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!(
            "/admin/realms/{}/identity-provider/instances/{}/mappers",
            args.realm, args.alias
        );
        let body = json!({
            "name": args.name,
            "identityProviderMapper": args.identity_provider_mapper,
            "config": args.config,
        });
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

    /// Delete a mapper by id from an identity provider.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:idp:write` (configurable); safety: destructive.
    #[tool(name = "idp.mappers.delete", description = "Delete a mapper by id.")]
    async fn identity_provider_mappers_delete(
        &self,
        Parameters(args): Parameters<IdentityProviderMapperDeleteArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.identity_providers.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!(
            "/admin/realms/{}/identity-provider/instances/{}/mappers/{}",
            args.realm, args.alias, args.mapper_id
        );
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }
}
