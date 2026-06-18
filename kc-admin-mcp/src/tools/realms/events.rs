use super::*;

#[rmcp::tool_router(router = tool_router_realms_events, vis = "pub")]
impl KcAdminMcp {
    /// Get realm events configuration.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:read` (configurable); safety: read-only.
    #[tool(
        name = "realm.events.config.get",
        description = "Get realm events config."
    )]
    pub(crate) async fn realm_events_config_get(
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

        let path = format!("/admin/realms/{}/events/config", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "config": payload })))
    }

    /// Update realm events configuration.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:write` (configurable); safety: writes realm configuration.
    #[tool(
        name = "realm.events.config.set",
        description = "Update realm events config."
    )]
    pub(crate) async fn realm_events_config_set(
        &self,
        Parameters(args): Parameters<RealmEventsConfigArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.realms.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!("/admin/realms/{}/events/config", args.realm);
        let body = serde_json::to_value(args.config)
            .map_err(|_| crate::McpError::internal_error("failed to serialize config", None))?;
        self.gateway
            .request_json(&ctx, Method::PUT, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// List active realm keys metadata.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:read` (configurable); safety: read-only.
    #[tool(
        name = "realm.keys.list",
        description = "List active realm keys metadata."
    )]
    pub(crate) async fn realm_keys_list(
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

        let path = format!("/admin/realms/{}/keys", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let keys: RealmKeysSummary = match serde_json::from_value::<RealmKeysResponse>(payload) {
            Ok(response) => RealmKeysSummary {
                active: response.active,
                keys: response
                    .keys
                    .unwrap_or_default()
                    .into_iter()
                    .map(|key| RealmKeySummary {
                        provider_id: key.provider_id,
                        provider_priority: key.provider_priority,
                        kid: key.kid,
                        status: key.status,
                        key_type: key.key_type,
                        algorithm: key.algorithm,
                        valid_to: key.valid_to,
                    })
                    .collect(),
            },
            Err(_) => RealmKeysSummary {
                active: None,
                keys: Vec::new(),
            },
        };

        Ok(CallToolResult::structured(json!({ "keys": keys })))
    }

    /// Test SMTP settings for a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:write` (configurable); safety: initiates SMTP connectivity checks.
    #[tool(
        name = "realm.smtp.test",
        description = "Test SMTP settings for a realm."
    )]
    pub(crate) async fn realm_smtp_test(
        &self,
        Parameters(args): Parameters<RealmSmtpTestArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let ctx = match auth_from_parts(&parts) {
            Ok(ctx) => ctx,
            Err(err) => return Ok(err),
        };
        let scopes = &self.config.scope_map.realms.write;
        if let Err(err) = require_scopes(&ctx, scopes) {
            return Ok(err);
        }
        if let Err(err) = require_roles_for_scopes(&ctx, scopes, &self.config) {
            return Ok(err);
        }

        let path = format!("/admin/realms/{}/testSMTPConnection", args.realm);
        let body = json!(args.settings);
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }
}
