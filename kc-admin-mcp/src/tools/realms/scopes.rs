use super::*;

#[mcp_toolkit_core::rmcp::tool_router(router = tool_router_realms_scopes, vis = "pub")]
impl KcAdminMcp {
    /// List default or optional client scopes for a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:admin` (configurable); safety: read-only.
    #[tool(
        name = "realm.default_scopes.list",
        description = "List realm default client scopes (default or optional)."
    )]
    pub(crate) async fn realm_default_scopes_list(
        &self,
        Parameters(args): Parameters<RealmDefaultScopesListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.realms.admin;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = realm_default_scopes_path(&args.realm, &args.kind);
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

    /// Add a client scope to a realm's default or optional scopes.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:admin` (configurable); safety: destructive.
    #[tool(
        name = "realm.default_scopes.add",
        description = "Add a client scope to a realm's default or optional scopes."
    )]
    pub(crate) async fn realm_default_scopes_add(
        &self,
        Parameters(args): Parameters<RealmDefaultScopesAddArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.realms.admin;
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
                    "realm.default_scopes.scope_not_found",
                    "Client scope not found.",
                    &ctx.request_id,
                ))
            }
        };

        // Keycloak adds realm default scopes by PUT-ing the clientScopeId into the appropriate
        // default scope collection (mirrors DELETE used by realm.default_scopes.remove).
        let path = realm_default_scope_member_path(&args.realm, &args.kind, &scope_id);
        self.gateway
            .request_json(&ctx, Method::PUT, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Remove a client scope from a realm's default or optional scopes.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:admin` (configurable); safety: destructive.
    #[tool(
        name = "realm.default_scopes.remove",
        description = "Remove a client scope from a realm's default or optional scopes."
    )]
    pub(crate) async fn realm_default_scopes_remove(
        &self,
        Parameters(args): Parameters<RealmDefaultScopesRemoveArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.realms.admin;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = realm_default_scope_member_path(&args.realm, &args.kind, &args.scope_id);
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "removed": true })))
    }
}
