use super::*;

#[mcp_toolkit_core::rmcp::tool_router(router = tool_router_users_groups, vis = "pub")]
impl KcAdminMcp {
    /// List group memberships for a user.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:read` (configurable); safety: read-only.
    #[tool(
        name = "users.groups.list",
        description = "List group membership for a user."
    )]
    pub(crate) async fn users_groups_list(
        &self,
        Parameters(args): Parameters<UsersGroupsListArgs>,
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

        let mut query = Vec::new();
        if let Some(brief) = args.brief_representation {
            query.push(("briefRepresentation".to_string(), brief.to_string()));
        }

        let path = format!("/admin/realms/{}/users/{}/groups", args.realm, args.user_id);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, query, None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let groups: Vec<UserGroupSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<UserGroupRepresentation>(item).ok())
                .map(UserGroupSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "groups": groups })))
    }

    /// Add a user to a group.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:write` (configurable); safety: writes group membership.
    #[tool(name = "users.groups.add", description = "Add a user to a group.")]
    pub(crate) async fn users_groups_add(
        &self,
        Parameters(args): Parameters<UsersGroupModifyArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        validate_uuid(&args.user_id, "user_id")?;
        validate_uuid(&args.group_id, "group_id")?;

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

        let path = format!(
            "/admin/realms/{}/users/{}/groups/{}",
            args.realm, args.user_id, args.group_id
        );
        self.gateway
            .request_json(&ctx, Method::PUT, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Remove a user from a group.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: none enforced in handler (expected `keycloak-admin:users:write`); safety: writes group membership.
    #[tool(
        name = "users.groups.remove",
        description = "Remove a user from a group."
    )]
    pub(crate) async fn users_groups_remove(
        &self,
        Parameters(args): Parameters<UsersGroupModifyArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        validate_uuid(&args.user_id, "user_id")?;
        validate_uuid(&args.group_id, "group_id")?;

        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };

        let path = format!(
            "/admin/realms/{}/users/{}/groups/{}",
            args.realm, args.user_id, args.group_id
        );
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }
}
