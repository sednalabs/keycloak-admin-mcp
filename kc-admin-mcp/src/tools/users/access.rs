use super::*;

#[mcp_toolkit_core::rmcp::tool_router(router = tool_router_users_access, vis = "pub")]
impl KcAdminMcp {
    /// List realm role mappings for a user.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:read` (configurable); safety: read-only.
    #[tool(
        name = "users.role_mappings.realm",
        description = "List realm role mappings for a user."
    )]
    pub(crate) async fn users_role_mappings_realm(
        &self,
        Parameters(args): Parameters<UsersGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        validate_uuid(&args.user_id, "user_id")?;

        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.users.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!(
            "/admin/realms/{}/users/{}/role-mappings/realm",
            args.realm, args.user_id
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

    /// List client role mappings for a user.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:read` (configurable); safety: read-only.
    #[tool(
        name = "users.role_mappings.clients",
        description = "List client role mappings for a user."
    )]
    pub(crate) async fn users_role_mappings_clients(
        &self,
        Parameters(args): Parameters<UsersGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        validate_uuid(&args.user_id, "user_id")?;

        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.users.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!(
            "/admin/realms/{}/users/{}/role-mappings",
            args.realm, args.user_id
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let client_mappings = payload
            .get("clientMappings")
            .and_then(|value| value.as_object());

        let mut clients = Vec::new();
        if let Some(mappings) = client_mappings {
            for (client_id, mapping_value) in mappings {
                let client_name = mapping_value
                    .get("client")
                    .and_then(|value| value.as_str())
                    .map(|value| value.to_string());
                let roles_value = mapping_value
                    .get("mappings")
                    .and_then(|value| value.as_array())
                    .cloned()
                    .unwrap_or_default();
                let roles = roles_value
                    .into_iter()
                    .map(role_summary_from_value)
                    .collect();
                clients.push(ClientRoleMappingSummary {
                    client_id: Some(client_id.to_string()),
                    client_name,
                    roles,
                });
            }
        }

        Ok(CallToolResult::structured(json!({ "clients": clients })))
    }

    /// List consents granted by a user.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:read` (configurable); safety: read-only.
    #[tool(
        name = "users.consent.list",
        description = "List consents granted by a user."
    )]
    pub(crate) async fn users_consent_list(
        &self,
        Parameters(args): Parameters<UsersGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        validate_uuid(&args.user_id, "user_id")?;

        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.users.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!(
            "/admin/realms/{}/users/{}/consents",
            args.realm, args.user_id
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let consents: Vec<UserConsentSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<UserConsentRepresentation>(item).ok())
                .map(UserConsentSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "consents": consents })))
    }

    /// List active sessions for a user.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:read` (configurable); safety: read-only.
    #[tool(name = "users.sessions.list", description = "List active sessions.")]
    pub(crate) async fn users_sessions_list(
        &self,
        Parameters(args): Parameters<UsersGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        validate_uuid(&args.user_id, "user_id")?;

        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.users.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!(
            "/admin/realms/{}/users/{}/sessions",
            args.realm, args.user_id
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let sessions: Vec<UserSessionSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<UserSessionRepresentation>(item).ok())
                .map(UserSessionSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "sessions": sessions })))
    }

    /// Logout a user from all sessions.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:write` (configurable); safety: terminates sessions.
    #[tool(
        name = "users.sessions.logout",
        description = "Logout a user from all sessions."
    )]
    pub(crate) async fn users_sessions_logout(
        &self,
        Parameters(args): Parameters<UsersGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        validate_uuid(&args.user_id, "user_id")?;

        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.users.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!("/admin/realms/{}/users/{}/logout", args.realm, args.user_id);
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }
}
