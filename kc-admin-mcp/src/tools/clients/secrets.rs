use super::*;

#[rmcp::tool_router(router = tool_router_clients_secrets, vis = "pub")]
impl KcAdminMcp {
    /// Fetch a client secret.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` + `keycloak-admin:clients:secrets` (configurable); safety: returns secrets and requires secret tools enabled.
    #[tool(name = "clients.secrets.get", description = "Fetch the client secret.")]
    pub(crate) async fn clients_secrets_get(
        &self,
        Parameters(args): Parameters<ClientsSecretArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let mut required = self.config.scope_map.clients.write.clone();
        required.extend(self.config.scope_map.clients.secrets.clone());
        if let Err(err) = require_scopes(&ctx, &required) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, &required, &self.config) {
            return Ok(err);
        }
        if let Err(err) = ensure_secret_tools_enabled(&ctx, &self.config) {
            return Ok(err);
        }

        let client_id = resolve_client_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.client_id.as_ref(),
        )
        .await?;
        let client_id = match client_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "clients.not_found",
                    "Client not found.",
                    &ctx.request_id,
                ))
            }
        };

        let path = format!(
            "/admin/realms/{}/clients/{}/client-secret",
            args.realm, client_id
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let secret = payload
            .get("value")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        Ok(CallToolResult::structured(json!({ "secret": secret })))
    }

    /// Generate a new client secret.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` + `keycloak-admin:clients:secrets` (configurable); safety: rotates secrets and requires secret tools enabled.
    #[tool(
        name = "clients.secrets.rotate",
        description = "Generate a new client secret (confirm=true)."
    )]
    pub(crate) async fn clients_secrets_rotate(
        &self,
        Parameters(args): Parameters<ClientsSecretRotateArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let mut required = self.config.scope_map.clients.write.clone();
        required.extend(self.config.scope_map.clients.secrets.clone());
        if let Err(err) = require_scopes(&ctx, &required) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, &required, &self.config) {
            return Ok(err);
        }
        if let Err(err) = ensure_secret_tools_enabled(&ctx, &self.config) {
            return Ok(err);
        }
        if !args.confirm {
            return Ok(tool_error(
                "clients.confirm_required",
                "confirm=true is required to rotate secrets.",
                &ctx.request_id,
            ));
        }

        let client_id = resolve_client_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.client_id.as_ref(),
        )
        .await?;
        let client_id = match client_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "clients.not_found",
                    "Client not found.",
                    &ctx.request_id,
                ))
            }
        };

        let path = format!(
            "/admin/realms/{}/clients/{}/client-secret",
            args.realm, client_id
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let secret = payload
            .get("value")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        Ok(CallToolResult::structured(json!({ "secret": secret })))
    }
}
