use super::*;

#[rmcp::tool_router(router = tool_router_users_password, vis = "pub")]
impl KcAdminMcp {
    /// Reset a user's password.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:write` (configurable); safety: writes credentials.
    #[tool(
        name = "users.reset_password",
        description = "Reset a user password (temporary by default)."
    )]
    pub(crate) async fn users_reset_password(
        &self,
        Parameters(args): Parameters<UsersResetPasswordArgs>,
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
        if args.new_password.trim().is_empty() {
            return Ok(tool_error(
                "users.reset_password.invalid_password",
                "new_password is required.",
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/users/{}/reset-password",
            args.realm, args.user_id
        );
        let body = json!({
            "type": "password",
            "value": args.new_password,
            "temporary": args.temporary.unwrap_or(true),
        });
        self.gateway
            .request_json(&ctx, Method::PUT, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "reset": true })))
    }

    /// Replace required actions for a user.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:users:write` (configurable); safety: writes account state.
    #[tool(
        name = "users.required_actions.set",
        description = "Replace the required actions list for a user."
    )]
    pub(crate) async fn users_required_actions_set(
        &self,
        Parameters(args): Parameters<UsersRequiredActionsArgs>,
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
        let body = json!({
            "requiredActions": args.actions,
        });
        self.gateway
            .request_json(&ctx, Method::PUT, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }
}
