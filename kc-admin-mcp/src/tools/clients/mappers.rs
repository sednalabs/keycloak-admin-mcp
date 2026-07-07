use super::*;

#[mcp_toolkit_core::rmcp::tool_router(router = tool_router_clients_mappers, vis = "pub")]
impl KcAdminMcp {
    /// List protocol mappers for a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
    #[tool(
        name = "clients.protocol_mappers.list",
        description = "List protocol mappers for a client."
    )]
    pub(crate) async fn clients_protocol_mappers_list(
        &self,
        Parameters(args): Parameters<ClientsProtocolMapperListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.clients.read;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
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
            "/admin/realms/{}/clients/{}/protocol-mappers/models",
            args.realm, client_id
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

    /// Add a protocol mapper to a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes mapper configuration.
    #[tool(
        name = "clients.protocol_mappers.add",
        description = "Add a protocol mapper to a client."
    )]
    pub(crate) async fn clients_protocol_mappers_add(
        &self,
        Parameters(args): Parameters<ClientsProtocolMapperAddArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.clients.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
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
            "/admin/realms/{}/clients/{}/protocol-mappers/models",
            args.realm, client_id
        );
        let body = json!({
            "name": args.name,
            "protocol": args.protocol,
            "protocolMapper": args.protocol_mapper,
            "config": args.config,
            "consentRequired": args.consent_required,
            "consentText": args.consent_text,
        });
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Delete a protocol mapper from a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive.
    #[tool(
        name = "clients.protocol_mappers.delete",
        description = "Delete a protocol mapper from a client."
    )]
    pub(crate) async fn clients_protocol_mappers_delete(
        &self,
        Parameters(args): Parameters<ClientsProtocolMapperDeleteArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.clients.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
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
            "/admin/realms/{}/clients/{}/protocol-mappers/models/{}",
            args.realm, client_id, args.mapper_id
        );
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Replace redirect URIs for a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes redirect URIs.
    #[tool(
        name = "clients.redirect_uris.update",
        description = "Replace redirect URIs for a client."
    )]
    pub(crate) async fn clients_redirect_uris_update(
        &self,
        Parameters(args): Parameters<ClientsRedirectUrisArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.clients.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
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

        let path = format!("/admin/realms/{}/clients/{}", args.realm, client_id);
        let body = json!({ "redirectUris": args.redirect_uris });
        self.gateway
            .request_json(&ctx, Method::PUT, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }
}
