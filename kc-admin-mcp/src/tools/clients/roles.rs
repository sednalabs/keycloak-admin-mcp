use super::*;

#[rmcp::tool_router(router = tool_router_clients_roles, vis = "pub")]
impl KcAdminMcp {
    /// List realm scope mappings for a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
    #[tool(
        name = "clients.scope_mappings.realm",
        description = "List realm scope mappings for a client."
    )]
    pub(crate) async fn clients_scope_mappings_realm(
        &self,
        Parameters(args): Parameters<ClientsScopesArgs>,
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
            "/admin/realms/{}/clients/{}/scope-mappings/realm",
            args.realm, client_id
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

    /// Add realm scope mappings to a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes realm role mappings.
    #[tool(
        name = "clients.scope_mappings.realm.add",
        description = "Add realm scope mappings to a client."
    )]
    pub(crate) async fn clients_scope_mappings_realm_add(
        &self,
        Parameters(args): Parameters<ClientsScopeMappingsRealmModifyArgs>,
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

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "clients.invalid_input",
                "role_names must include at least one role.",
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

        let resolved = resolve_realm_roles(self, &ctx, &args.realm, &role_names).await?;
        if !resolved.missing.is_empty() {
            return Ok(tool_error(
                "clients.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/clients/{}/scope-mappings/realm",
            args.realm, client_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Remove realm scope mappings from a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive.
    #[tool(
        name = "clients.scope_mappings.realm.delete",
        description = "Remove realm scope mappings from a client."
    )]
    pub(crate) async fn clients_scope_mappings_realm_delete(
        &self,
        Parameters(args): Parameters<ClientsScopeMappingsRealmModifyArgs>,
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

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "clients.invalid_input",
                "role_names must include at least one role.",
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

        let resolved = resolve_realm_roles(self, &ctx, &args.realm, &role_names).await?;
        if !resolved.missing.is_empty() {
            return Ok(tool_error(
                "clients.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/clients/{}/scope-mappings/realm",
            args.realm, client_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// List client scope mappings for a client and role container.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
    #[tool(
        name = "clients.scope_mappings.client",
        description = "List client scope mappings for a client and role container."
    )]
    pub(crate) async fn clients_scope_mappings_client(
        &self,
        Parameters(args): Parameters<ClientsScopeMappingsClientArgs>,
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

        let target_client_id = resolve_client_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.client_id.as_ref(),
        )
        .await?;
        let target_client_id = match target_client_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "clients.not_found",
                    "Client not found.",
                    &ctx.request_id,
                ))
            }
        };

        let role_client_id = match resolve_client_id(
            self,
            &ctx,
            &args.realm,
            args.role_client_unique_id.as_ref(),
            args.role_client_id.as_ref(),
        )
        .await?
        {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "clients.role_client_not_found",
                    "Role client not found.",
                    &ctx.request_id,
                ))
            }
        };

        let path = format!(
            "/admin/realms/{}/clients/{}/scope-mappings/clients/{}",
            args.realm, target_client_id, role_client_id
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

    /// Add client role scope mappings to a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes client role mappings.
    #[tool(
        name = "clients.scope_mappings.client.add",
        description = "Add client role scope mappings to a client."
    )]
    pub(crate) async fn clients_scope_mappings_client_add(
        &self,
        Parameters(args): Parameters<ClientsScopeMappingsClientModifyArgs>,
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

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "clients.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }

        let target_client_id = resolve_client_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.client_id.as_ref(),
        )
        .await?;
        let target_client_id = match target_client_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "clients.not_found",
                    "Client not found.",
                    &ctx.request_id,
                ))
            }
        };

        let role_client_id = match resolve_client_id(
            self,
            &ctx,
            &args.realm,
            args.role_client_unique_id.as_ref(),
            args.role_client_id.as_ref(),
        )
        .await?
        {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "clients.role_client_not_found",
                    "Role client not found.",
                    &ctx.request_id,
                ))
            }
        };

        let resolved =
            resolve_client_roles(self, &ctx, &args.realm, &role_client_id, &role_names).await?;
        if !resolved.missing.is_empty() {
            return Ok(tool_error(
                "clients.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/clients/{}/scope-mappings/clients/{}",
            args.realm, target_client_id, role_client_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Remove client role scope mappings from a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive.
    #[tool(
        name = "clients.scope_mappings.client.delete",
        description = "Remove client role scope mappings from a client."
    )]
    pub(crate) async fn clients_scope_mappings_client_delete(
        &self,
        Parameters(args): Parameters<ClientsScopeMappingsClientModifyArgs>,
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

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "clients.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }

        let target_client_id = resolve_client_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.client_id.as_ref(),
        )
        .await?;
        let target_client_id = match target_client_id {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "clients.not_found",
                    "Client not found.",
                    &ctx.request_id,
                ))
            }
        };

        let role_client_id = match resolve_client_id(
            self,
            &ctx,
            &args.realm,
            args.role_client_unique_id.as_ref(),
            args.role_client_id.as_ref(),
        )
        .await?
        {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "clients.role_client_not_found",
                    "Role client not found.",
                    &ctx.request_id,
                ))
            }
        };

        let resolved =
            resolve_client_roles(self, &ctx, &args.realm, &role_client_id, &role_names).await?;
        if !resolved.missing.is_empty() {
            return Ok(tool_error(
                "clients.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/clients/{}/scope-mappings/clients/{}",
            args.realm, target_client_id, role_client_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// List role mappings for a client service account.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
    #[tool(
        name = "clients.service_account.roles",
        description = "List role mappings for a client service account."
    )]
    pub(crate) async fn clients_service_account_roles(
        &self,
        Parameters(args): Parameters<ClientsServiceAccountArgs>,
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

        let user_id = resolve_service_account_user_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.client_id.as_ref(),
        )
        .await?;
        let user_id = match user_id {
            ServiceAccountLookup::Found(id) => id,
            ServiceAccountLookup::NotFound => {
                return Ok(tool_error(
                    "clients.service_account_not_found",
                    "Service account user not found.",
                    &ctx.request_id,
                ))
            }
            ServiceAccountLookup::NotEnabled { detail } => {
                return Ok(service_account_disabled_error(
                    &ctx.request_id,
                    detail.as_deref(),
                ))
            }
        };

        let path = format!(
            "/admin/realms/{}/users/{}/role-mappings",
            args.realm, user_id
        );
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let mappings = serde_json::from_value::<RoleMappings>(payload).map_err(|_| {
            crate::McpError::internal_error("unexpected response from gateway", None)
        })?;
        let realm_roles: Vec<RoleSummary> = mappings
            .realm_mappings
            .unwrap_or_default()
            .into_iter()
            .map(RoleSummary::from)
            .collect();
        let mut client_entries = Vec::new();
        if let Some(client_mappings) = mappings.client_mappings {
            for (client_id, mapping) in client_mappings {
                let roles: Vec<RoleSummary> = mapping
                    .mappings
                    .unwrap_or_default()
                    .into_iter()
                    .map(RoleSummary::from)
                    .collect();
                client_entries.push(ServiceAccountClientSummary {
                    client_id,
                    client_name: mapping.client,
                    roles,
                });
            }
        }

        Ok(CallToolResult::structured(json!(
            ServiceAccountRolesSummary {
                realm: realm_roles,
                clients: client_entries,
            }
        )))
    }

    /// Add realm roles to a client service account.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes realm role mappings.
    #[tool(
        name = "clients.service_account.roles.realm.add",
        description = "Add realm roles to a client service account."
    )]
    pub(crate) async fn clients_service_account_roles_realm_add(
        &self,
        Parameters(args): Parameters<ClientsServiceAccountRealmArgs>,
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

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "clients.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }

        let user_id = resolve_service_account_user_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.client_id.as_ref(),
        )
        .await?;
        let user_id = match user_id {
            ServiceAccountLookup::Found(id) => id,
            ServiceAccountLookup::NotFound => {
                return Ok(tool_error(
                    "clients.service_account_not_found",
                    "Service account user not found.",
                    &ctx.request_id,
                ))
            }
            ServiceAccountLookup::NotEnabled { detail } => {
                return Ok(service_account_disabled_error(
                    &ctx.request_id,
                    detail.as_deref(),
                ))
            }
        };

        let resolved = resolve_realm_roles(self, &ctx, &args.realm, &role_names).await?;
        if !resolved.missing.is_empty() {
            return Ok(tool_error(
                "clients.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/users/{}/role-mappings/realm",
            args.realm, user_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Remove realm roles from a client service account.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive.
    #[tool(
        name = "clients.service_account.roles.realm.remove",
        description = "Remove realm roles from a client service account."
    )]
    pub(crate) async fn clients_service_account_roles_realm_remove(
        &self,
        Parameters(args): Parameters<ClientsServiceAccountRealmArgs>,
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

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "clients.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }

        let user_id = resolve_service_account_user_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.client_id.as_ref(),
        )
        .await?;
        let user_id = match user_id {
            ServiceAccountLookup::Found(id) => id,
            ServiceAccountLookup::NotFound => {
                return Ok(tool_error(
                    "clients.service_account_not_found",
                    "Service account user not found.",
                    &ctx.request_id,
                ))
            }
            ServiceAccountLookup::NotEnabled { detail } => {
                return Ok(service_account_disabled_error(
                    &ctx.request_id,
                    detail.as_deref(),
                ))
            }
        };

        let resolved = resolve_realm_roles(self, &ctx, &args.realm, &role_names).await?;
        if !resolved.missing.is_empty() {
            return Ok(tool_error(
                "clients.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/users/{}/role-mappings/realm",
            args.realm, user_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Add client roles to a client service account.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes client role mappings.
    #[tool(
        name = "clients.service_account.roles.client.add",
        description = "Add client roles to a client service account."
    )]
    pub(crate) async fn clients_service_account_roles_client_add(
        &self,
        Parameters(args): Parameters<ClientsServiceAccountClientArgs>,
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

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "clients.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }

        let user_id = resolve_service_account_user_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.client_id.as_ref(),
        )
        .await?;
        let user_id = match user_id {
            ServiceAccountLookup::Found(id) => id,
            ServiceAccountLookup::NotFound => {
                return Ok(tool_error(
                    "clients.service_account_not_found",
                    "Service account user not found.",
                    &ctx.request_id,
                ))
            }
            ServiceAccountLookup::NotEnabled { detail } => {
                return Ok(service_account_disabled_error(
                    &ctx.request_id,
                    detail.as_deref(),
                ))
            }
        };

        let role_client_id = match resolve_client_id(
            self,
            &ctx,
            &args.realm,
            args.role_client_unique_id.as_ref(),
            args.role_client_id.as_ref(),
        )
        .await?
        {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "clients.role_client_not_found",
                    "Role client not found.",
                    &ctx.request_id,
                ))
            }
        };

        let resolved =
            resolve_client_roles(self, &ctx, &args.realm, &role_client_id, &role_names).await?;
        if !resolved.missing.is_empty() {
            return Ok(tool_error(
                "clients.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/users/{}/role-mappings/clients/{}",
            args.realm, user_id, role_client_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }

    /// Remove client roles from a client service account.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive.
    #[tool(
        name = "clients.service_account.roles.client.remove",
        description = "Remove client roles from a client service account."
    )]
    pub(crate) async fn clients_service_account_roles_client_remove(
        &self,
        Parameters(args): Parameters<ClientsServiceAccountClientArgs>,
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

        let role_names = args.role_names.unwrap_or_default();
        if role_names.is_empty() {
            return Ok(tool_error(
                "clients.invalid_input",
                "role_names must include at least one role.",
                &ctx.request_id,
            ));
        }

        let user_id = resolve_service_account_user_id(
            self,
            &ctx,
            &args.realm,
            args.id.as_ref(),
            args.client_id.as_ref(),
        )
        .await?;
        let user_id = match user_id {
            ServiceAccountLookup::Found(id) => id,
            ServiceAccountLookup::NotFound => {
                return Ok(tool_error(
                    "clients.service_account_not_found",
                    "Service account user not found.",
                    &ctx.request_id,
                ))
            }
            ServiceAccountLookup::NotEnabled { detail } => {
                return Ok(service_account_disabled_error(
                    &ctx.request_id,
                    detail.as_deref(),
                ))
            }
        };

        let role_client_id = match resolve_client_id(
            self,
            &ctx,
            &args.realm,
            args.role_client_unique_id.as_ref(),
            args.role_client_id.as_ref(),
        )
        .await?
        {
            Some(id) => id,
            None => {
                return Ok(tool_error(
                    "clients.role_client_not_found",
                    "Role client not found.",
                    &ctx.request_id,
                ))
            }
        };

        let resolved =
            resolve_client_roles(self, &ctx, &args.realm, &role_client_id, &role_names).await?;
        if !resolved.missing.is_empty() {
            return Ok(tool_error(
                "clients.roles_missing",
                &format!("Missing roles: {}", resolved.missing.join(", ")),
                &ctx.request_id,
            ));
        }

        let path = format!(
            "/admin/realms/{}/users/{}/role-mappings/clients/{}",
            args.realm, user_id, role_client_id
        );
        let body = serde_json::to_value(resolved.roles)
            .map_err(|_| crate::McpError::internal_error("failed to serialize roles", None))?;
        self.gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        Ok(CallToolResult::structured(json!({ "ok": true })))
    }
}
