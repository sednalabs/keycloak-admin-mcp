use super::*;

#[mcp_toolkit_core::rmcp::tool_router(router = tool_router_users_core, vis = "pub")]
impl KcAdminMcp {
    /// List users within a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:read` (configurable); safety: read-only.
    #[tool(name = "users.list", description = "List users within a realm.")]
    pub(crate) async fn users_list(
        &self,
        Parameters(args): Parameters<UsersListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;

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

        let mut query = Vec::new();
        if let Some(search) = args.search {
            query.push(("search".to_string(), search));
        }
        if let Some(max) = args.max {
            query.push(("max".to_string(), max.to_string()));
        }

        let path = format!("/admin/realms/{}/users", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, query, None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let users: Vec<UserSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<UserRepresentation>(item).ok())
                .map(UserSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({
            "users": users,
        })))
    }

    /// Get a user by id.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:read` (configurable); safety: read-only.
    #[tool(name = "users.get", description = "Get a user by id.")]
    pub(crate) async fn users_get(
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

        let path = format!("/admin/realms/{}/users/{}", args.realm, args.user_id);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let summary = serde_json::from_value::<UserRepresentation>(payload)
            .map(UserSummary::from)
            .map_err(|_| {
                crate::McpError::internal_error("unexpected response from gateway", None)
            })?;

        Ok(CallToolResult::structured(json!({ "user": summary })))
    }

    /// Create a user in a realm.
    ///
    /// # Security
    /// * **Write Access**: Gated by `keycloak-admin:users:write`.
    /// * **Input Sanitization**: Validates `username` against path traversal.
    #[tool(name = "users.create", description = "Create a user in a realm.")]
    pub(crate) async fn users_create(
        &self,
        Parameters(args): Parameters<UsersCreateArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        validate_no_path_traversal(&args.username, "username")?;

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

        let path = format!("/admin/realms/{}/users", args.realm);
        let body = json!({
            "username": args.username,
            "email": args.email,
            "firstName": args.first_name,
            "lastName": args.last_name,
            "enabled": args.enabled.unwrap_or(true),
        });
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(tool_text_result("User created."))
    }

    /// Delete a user by id.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:write` (configurable); safety: destructive.
    #[tool(name = "users.delete", description = "Delete a user by id.")]
    pub(crate) async fn users_delete(
        &self,
        Parameters(args): Parameters<UsersDeleteArgs>,
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

        let path = format!("/admin/realms/{}/users/{}", args.realm, args.user_id);
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "deleted": true })))
    }
}
