use super::*;

async fn configured_registration_policy_components(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
) -> Result<Vec<serde_json::Value>, crate::McpError> {
    let path = format!("/admin/realms/{realm}/components");
    let query = vec![(
        "type".to_string(),
        CLIENT_REG_POLICY_COMPONENT_TYPE.to_string(),
    )];
    let payload = mcp
        .gateway
        .request_json(ctx, Method::GET, &path, query, None)
        .await
        .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;
    Ok(match payload {
        serde_json::Value::Array(items) => items,
        _ => Vec::new(),
    })
}

#[mcp_toolkit_core::rmcp::tool_router(router = tool_router_realms_registration, vis = "pub")]
impl KcAdminMcp {
    /// List available client registration policy provider definitions for a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:read` (configurable); safety: read-only.
    #[tool(
        name = "client_registration.policy_providers.list",
        description = "List available client registration policy provider definitions for a realm. This does not return configured policy instances."
    )]
    pub(crate) async fn client_registration_policy_providers_list(
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

        let path = format!(
            "/admin/realms/{}/client-registration-policy/providers",
            args.realm
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let providers: Vec<ClientRegistrationPolicyProviderSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| {
                    serde_json::from_value::<ClientRegistrationPolicyProvider>(item).ok()
                })
                .map(|provider| ClientRegistrationPolicyProviderSummary {
                    id: provider.id,
                    help_text: provider
                        .help_text
                        .map(|value| value.chars().take(MAX_DESC_LEN).collect()),
                })
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(
            json!({ "providers": providers }),
        ))
    }

    /// List configured client registration policy components for a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:read` (configurable); safety: read-only.
    #[tool(
        name = "client_registration.policies.list",
        description = "List configured client registration policy instances, including component ids and round-trip configuration. Optional selectors filter by id, name, or provider id."
    )]
    pub(crate) async fn client_registration_policies_list(
        &self,
        Parameters(args): Parameters<ClientRegistrationPolicyListArgs>,
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

        let components = configured_registration_policy_components(self, &ctx, &args.realm).await?;
        let selected = if args.id.is_none() && args.name.is_none() && args.provider_id.is_none() {
            (0..components.len()).collect::<Vec<_>>()
        } else {
            match_registration_policy_components(
                &components,
                args.id.as_deref(),
                args.name.as_deref(),
                args.provider_id.as_deref(),
            )
        };
        let policies = selected
            .into_iter()
            .filter_map(|idx| components.get(idx))
            .filter_map(summarize_registration_policy_component)
            .collect::<Vec<_>>();

        Ok(CallToolResult::structured(json!({ "policies": policies })))
    }

    /// Fetch one configured client registration policy component for a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:read` (configurable); safety: read-only.
    #[tool(
        name = "client_registration.policies.get",
        description = "Fetch one configured client registration policy instance by id, name, or provider id. Omitting selectors targets the default Allowed Client Scopes provider."
    )]
    pub(crate) async fn client_registration_policies_get(
        &self,
        Parameters(args): Parameters<ClientRegistrationPolicyGetArgs>,
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

        let provider_id =
            resolve_registration_policy_provider_id(&args.id, &args.name, &args.provider_id);
        let components = configured_registration_policy_components(self, &ctx, &args.realm).await?;
        let matches = match_registration_policy_components(
            &components,
            args.id.as_deref(),
            args.name.as_deref(),
            provider_id.as_deref(),
        );
        if matches.is_empty() {
            return Ok(tool_error(
                "client_registration.policies.not_found",
                "No matching client registration policy component found.",
                &ctx.request_id,
            ));
        }
        if matches.len() > 1 {
            return Ok(tool_error(
                "client_registration.policies.ambiguous",
                "Multiple registration policy components matched. Specify id or name.",
                &ctx.request_id,
            ));
        }
        let policy = matches
            .first()
            .and_then(|idx| components.get(*idx))
            .and_then(summarize_registration_policy_component)
            .ok_or_else(|| crate::McpError::internal_error("component is not an object", None))?;

        Ok(CallToolResult::structured(json!({ "policy": policy })))
    }

    /// Create a client registration policy component (Allowed Client Scopes).
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:write` (configurable); safety: writes registration policy config.
    #[tool(
        name = "client_registration.policies.create",
        description = "Create client registration policy configuration (Allowed Client Scopes)."
    )]
    pub(crate) async fn client_registration_policies_create(
        &self,
        Parameters(args): Parameters<ClientRegistrationPolicyCreateArgs>,
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

        if args.allowed_scopes.is_empty() && args.allow_default_scopes.is_none() {
            return Ok(tool_error(
                "client_registration.policies.create.no_changes",
                "allowed_scopes or allow_default_scopes must be set.",
                &ctx.request_id,
            ));
        }

        let provider_id = args
            .provider_id
            .clone()
            .unwrap_or_else(|| DEFAULT_ALLOWED_CLIENT_SCOPES_PROVIDER.to_string());
        let name = args.name.clone().unwrap_or_else(|| provider_id.clone());

        let realm_path = format!("/admin/realms/{}", args.realm);
        let realm_payload = self
            .gateway
            .request_json(&ctx, Method::GET, &realm_path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;
        let parent_id = realm_payload
            .get("id")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
            .filter(|value| !value.trim().is_empty());
        let parent_id = match parent_id {
            Some(value) => value,
            None => {
                return Ok(tool_error(
                    "client_registration.policies.missing_parent",
                    "Realm id missing; cannot create policy component.",
                    &ctx.request_id,
                ))
            }
        };

        let allowed_scopes = args.allowed_scopes.clone();
        let mut config = serde_json::Map::new();
        if !allowed_scopes.is_empty() {
            set_config_list(
                &mut config,
                &CONFIG_ALLOWED_CLIENT_SCOPES_KEYS,
                allowed_scopes.clone(),
            );
        }
        if let Some(allow_default_scopes) = args.allow_default_scopes {
            set_config_bool(
                &mut config,
                &CONFIG_ALLOW_DEFAULT_SCOPES_KEYS,
                allow_default_scopes,
            );
        }

        let body = json!({
            "name": name.clone(),
            "providerId": provider_id.clone(),
            "providerType": CLIENT_REG_POLICY_COMPONENT_TYPE,
            "parentId": parent_id,
            "config": config,
        });
        let path = format!("/admin/realms/{}/components", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let id = payload
            .get("id")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        Ok(CallToolResult::structured(json!({
            "ok": true,
            "id": id,
            "provider_id": provider_id,
            "name": name,
            "allowed_scopes": allowed_scopes,
            "allow_default_scopes": args.allow_default_scopes,
        })))
    }

    /// Update the Allowed Client Scopes client registration policy.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:write` (configurable); safety: writes registration policy config.
    #[tool(
        name = "client_registration.policies.update",
        description = "Update client registration policy configuration (Allowed Client Scopes)."
    )]
    pub(crate) async fn client_registration_policies_update(
        &self,
        Parameters(args): Parameters<ClientRegistrationPolicyUpdateArgs>,
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

        if args.allowed_scopes.is_empty() && args.allow_default_scopes.is_none() {
            return Ok(tool_error(
                "client_registration.policies.update.no_changes",
                "allowed_scopes or allow_default_scopes must be set.",
                &ctx.request_id,
            ));
        }

        let provider_id =
            resolve_registration_policy_provider_id(&args.id, &args.name, &args.provider_id);

        let components = configured_registration_policy_components(self, &ctx, &args.realm).await?;

        let matches = match_registration_policy_components(
            &components,
            args.id.as_deref(),
            args.name.as_deref(),
            provider_id.as_deref(),
        );

        if matches.is_empty() {
            return Ok(tool_error(
                "client_registration.policies.not_found",
                "No matching client registration policy component found.",
                &ctx.request_id,
            ));
        }
        if matches.len() > 1 {
            return Ok(tool_error(
                "client_registration.policies.ambiguous",
                "Multiple registration policy components matched. Specify id or name.",
                &ctx.request_id,
            ));
        }

        let idx = matches[0];
        let mut component = components
            .get(idx)
            .cloned()
            .ok_or_else(|| crate::McpError::internal_error("component not found", None))?;

        {
            let object = component.as_object_mut().ok_or_else(|| {
                crate::McpError::internal_error("component is not an object", None)
            })?;
            let config_value = object
                .entry("config".to_string())
                .or_insert_with(|| serde_json::Value::Object(Default::default()));
            let config = config_value.as_object_mut().ok_or_else(|| {
                crate::McpError::internal_error("component config is not an object", None)
            })?;

            set_config_list(
                config,
                &CONFIG_ALLOWED_CLIENT_SCOPES_KEYS,
                args.allowed_scopes.clone(),
            );
            if let Some(allow_default_scopes) = args.allow_default_scopes {
                set_config_bool(
                    config,
                    &CONFIG_ALLOW_DEFAULT_SCOPES_KEYS,
                    allow_default_scopes,
                );
            }
        }

        let component_id = component
            .get("id")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        if component_id.is_empty() {
            return Ok(tool_error(
                "client_registration.policies.missing_id",
                "Component id is missing; cannot update policy.",
                &ctx.request_id,
            ));
        }

        let update_path = format!("/admin/realms/{}/components/{}", args.realm, component_id);
        self.gateway
            .request_json(&ctx, Method::PUT, &update_path, Vec::new(), Some(component))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({
            "ok": true,
            "id": component_id,
            "provider_id": provider_id,
            "allowed_scopes": args.allowed_scopes,
            "allow_default_scopes": args.allow_default_scopes,
        })))
    }

    /// Delete a client registration policy component.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:write` (configurable); safety: destructive.
    #[tool(
        name = "client_registration.policies.delete",
        description = "Delete client registration policy configuration."
    )]
    pub(crate) async fn client_registration_policies_delete(
        &self,
        Parameters(args): Parameters<ClientRegistrationPolicyDeleteArgs>,
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

        let provider_id =
            resolve_registration_policy_provider_id(&args.id, &args.name, &args.provider_id);

        let components = configured_registration_policy_components(self, &ctx, &args.realm).await?;

        let matches = match_registration_policy_components(
            &components,
            args.id.as_deref(),
            args.name.as_deref(),
            provider_id.as_deref(),
        );
        if matches.is_empty() {
            return Ok(tool_error(
                "client_registration.policies.not_found",
                "No matching client registration policy component found.",
                &ctx.request_id,
            ));
        }
        if matches.len() > 1 {
            return Ok(tool_error(
                "client_registration.policies.ambiguous",
                "Multiple registration policy components matched. Specify id or name.",
                &ctx.request_id,
            ));
        }

        let idx = matches[0];
        let component = components
            .get(idx)
            .cloned()
            .ok_or_else(|| crate::McpError::internal_error("component not found", None))?;
        let component_id = component
            .get("id")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        if component_id.is_empty() {
            return Ok(tool_error(
                "client_registration.policies.missing_id",
                "Component id is missing; cannot delete policy.",
                &ctx.request_id,
            ));
        }

        let delete_path = format!("/admin/realms/{}/components/{}", args.realm, component_id);
        self.gateway
            .request_json(&ctx, Method::DELETE, &delete_path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({
            "ok": true,
            "id": component_id,
        })))
    }

    /// List client initial access tokens for a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:admin` (configurable); safety: read-only.
    #[tool(
        name = "client_initial_access.list",
        description = "List client initial access tokens for a realm."
    )]
    pub(crate) async fn client_initial_access_list(
        &self,
        Parameters(args): Parameters<RealmArgs>,
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

        let path = format!("/admin/realms/{}/clients-initial-access", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let tokens: Vec<ClientInitialAccessSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| {
                    serde_json::from_value::<ClientInitialAccessRepresentation>(item).ok()
                })
                .map(|token| ClientInitialAccessSummary {
                    id: token.id,
                    timestamp: token.timestamp,
                    expiration: token.expiration,
                    count: token.count,
                    remaining_count: token.remaining_count,
                })
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "tokens": tokens })))
    }

    /// Create a client initial access token.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:admin` (configurable); safety: issues credentials.
    #[tool(
        name = "client_initial_access.create",
        description = "Create a client initial access token."
    )]
    pub(crate) async fn client_initial_access_create(
        &self,
        Parameters(args): Parameters<ClientInitialAccessCreateArgs>,
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

        let body = json!({
            "count": args.count,
            "expiration": args.expiration,
        });
        let path = format!("/admin/realms/{}/clients-initial-access", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let id = payload
            .get("id")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());
        let token = payload
            .get("token")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        Ok(CallToolResult::structured(
            json!({ "id": id, "token": token }),
        ))
    }

    /// Delete a client initial access token.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:realm:admin` (configurable); safety: destructive.
    #[tool(
        name = "client_initial_access.delete",
        description = "Delete a client initial access token."
    )]
    pub(crate) async fn client_initial_access_delete(
        &self,
        Parameters(args): Parameters<ClientInitialAccessDeleteArgs>,
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

        if args.id.trim().is_empty() {
            return Ok(tool_error(
                "client_initial_access.invalid_id",
                "id is required.",
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/clients-initial-access/{}",
            args.realm, args.id
        );
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }
}
