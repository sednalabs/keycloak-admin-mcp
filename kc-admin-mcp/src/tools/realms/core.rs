use super::*;

#[rmcp::tool_router(router = tool_router_realms_core, vis = "pub")]
impl KcAdminMcp {
    /// List all realms.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:read` (configurable); safety: read-only.
    #[tool(name = "realms.list", description = "List all realms.")]
    pub(crate) async fn realms_list(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.realms.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, "/admin/realms", Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let realms: Vec<RealmSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<RealmRepresentation>(item).ok())
                .map(|realm| RealmSummary {
                    id: realm.id,
                    realm: realm.realm,
                })
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "realms": realms })))
    }

    /// List authentication flows for a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:read` (configurable); safety: read-only.
    #[tool(
        name = "realm.authentication_flows.list",
        description = "List authentication flows for a realm."
    )]
    pub(crate) async fn realm_authentication_flows_list(
        &self,
        Parameters(args): Parameters<RealmArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.realms.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!("/admin/realms/{}/authentication/flows", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let flows: Vec<AuthFlowSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<AuthFlowRepresentation>(item).ok())
                .map(|flow| AuthFlowSummary {
                    id: flow.id,
                    alias: flow.alias,
                    description: flow
                        .description
                        .map(|value| value.chars().take(MAX_DESC_LEN).collect()),
                    provider_id: flow.provider_id,
                    top_level: flow.top_level,
                    built_in: flow.built_in,
                })
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "flows": flows })))
    }
}
