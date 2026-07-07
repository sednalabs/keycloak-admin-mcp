use super::*;
use crate::errors::tool_error_with_context;
use regex::Regex;
use uuid::Uuid;

#[mcp_toolkit_core::rmcp::tool_router(router = tool_router_clients_core, vis = "pub")]
impl KcAdminMcp {
    /// List clients within a realm.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
    #[tool(name = "clients.list", description = "List clients within a realm.")]
    pub(crate) async fn clients_list(
        &self,
        Parameters(args): Parameters<ClientsListArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;

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

        let mut query = Vec::new();
        if let Some(search) = args.search {
            query.push(("search".to_string(), search));
        }
        if let Some(max) = args.max {
            query.push(("max".to_string(), max.to_string()));
        }

        let path = format!("/admin/realms/{}/clients", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, query, None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let clients: Vec<ClientSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<ClientRepresentation>(item).ok())
                .map(ClientSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        Ok(CallToolResult::structured(json!({ "clients": clients })))
    }

    /// Search clients with deterministic ranking by partial `clientId`/`name`.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
    #[tool(
        name = "clients.search",
        description = "Search clients by ID or clientId."
    )]
    pub(crate) async fn clients_search(
        &self,
        Parameters(args): Parameters<ClientsSearchArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        let query = args.query.trim();
        if query.is_empty() {
            return Ok(tool_error_with_context(
                "clients.invalid_input",
                "query is required.",
                "req-client-search",
                Some("clients"),
                None,
                None,
                Some(json!({
                    "hint": "Provide a non-empty query and optional limit"
                })),
            ));
        }

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

        let mut query_params = vec![("search".to_string(), query.to_string())];
        if let Some(limit) = args.limit {
            if limit == 0 || limit > 100 {
                return Ok(tool_error_with_context(
                    "clients.invalid_input",
                    "limit must be between 1 and 100.",
                    &ctx.request_id,
                    Some("clients"),
                    None,
                    None,
                    Some(json!({
                        "limit": limit,
                    })),
                ));
            }
            query_params.push(("max".to_string(), limit.to_string()));
        }

        let path = format!("/admin/realms/{}/clients", args.realm);
        let mut clients = Vec::new();
        let id_query = Uuid::parse_str(query).ok();
        let exact_uuid_match = id_query.is_some();

        if let Some(id_query) = id_query {
            let lookup_path = format!("/admin/realms/{}/clients/{}", args.realm, id_query);
            match self
                .gateway
                .request_json(&ctx, Method::GET, &lookup_path, Vec::new(), None)
                .await
            {
                Ok(payload) => {
                    if let Ok(client) = serde_json::from_value::<ClientRepresentation>(payload) {
                        clients.push(ClientSummary::from(client));
                    }
                }
                Err(crate::gateway::GatewayError::Upstream { status, summary }) => {
                    if status != 404 {
                        return Err(crate::McpError::internal_error(
                            "gateway request failed",
                            Some(json!({
                                "upstream_status": status,
                                "upstream_error": summary,
                            })),
                        ));
                    }
                }
                Err(_) => {
                    return Err(crate::McpError::internal_error(
                        "gateway request failed",
                        None,
                    ));
                }
            }
        }

        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, query_params, None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let mut fetched_clients: Vec<ClientSummary> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<ClientRepresentation>(item).ok())
                .map(ClientSummary::from)
                .collect(),
            _ => Vec::new(),
        };

        for client in fetched_clients.drain(..) {
            let is_duplicate = client
                .id
                .as_ref()
                .and_then(|id| {
                    clients
                        .iter()
                        .find(|existing| existing.id.as_ref() == Some(id))
                })
                .is_some();
            if !is_duplicate {
                clients.push(client);
            }
        }
        if exact_uuid_match {
            let normalized_query = query.to_ascii_lowercase();
            clients.retain(|client| {
                client
                    .id
                    .as_ref()
                    .is_some_and(|id| id.eq_ignore_ascii_case(&normalized_query))
                    || client
                        .client_id
                        .as_ref()
                        .is_some_and(|client_id| client_id.eq_ignore_ascii_case(&normalized_query))
            });
        }

        let results = rank_client_search_results(clients, query, args.limit);
        Ok(CallToolResult::structured(json!({
            "query": query,
            "results": results,
        })))
    }

    /// Get a client by id or clientId.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
    #[tool(name = "clients.get", description = "Get a client by id or clientId.")]
    pub(crate) async fn clients_get(
        &self,
        Parameters(args): Parameters<ClientsGetArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        if let Some(id) = &args.id {
            validate_uuid(id, "id")?;
        }
        if let Some(client_id) = &args.client_id {
            validate_no_path_traversal(client_id, "client_id")?;
        }

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

        let path = format!("/admin/realms/{}/clients/{}", args.realm, client_id);
        let payload = match self
            .gateway
            .request_json(&ctx, Method::GET, &path, Vec::new(), None)
            .await
        {
            Ok(payload) => payload,
            Err(crate::gateway::GatewayError::Upstream { status, .. }) if status == 404 => {
                return Ok(tool_error(
                    "clients.not_found",
                    "Client not found.",
                    &ctx.request_id,
                ));
            }
            Err(err) => {
                return Err(match err {
                    crate::gateway::GatewayError::Upstream { status, summary } => {
                        crate::McpError::internal_error(
                            "gateway request failed",
                            Some(json!({
                                "upstream_status": status,
                                "upstream_error": summary,
                            })),
                        )
                    }
                    _ => crate::McpError::internal_error("gateway request failed", None),
                })
            }
        };

        let summary = serde_json::from_value::<ClientRepresentation>(payload)
            .map(ClientSummary::from)
            .map_err(|_| {
                crate::McpError::internal_error("unexpected response from gateway", None)
            })?;

        Ok(CallToolResult::structured(json!({ "client": summary })))
    }

    /// Create a new client in a realm.
    ///
    /// # Security
    /// * **Write Access**: Gated by `keycloak-admin:clients:write`.
    #[tool(
        name = "clients.create",
        description = "Create a new client in a realm."
    )]
    pub(crate) async fn clients_create(
        &self,
        Parameters(args): Parameters<ClientsCreateArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        validate_no_path_traversal(&args.client_id, "client_id")?;
        if let Some(name) = &args.name {
            validate_no_path_traversal(name, "name")?;
        }

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

        let body = json!({
            "clientId": args.client_id,
            "name": args.name,
            "protocol": args.protocol.unwrap_or_else(|| "openid-connect".to_string()),
            "publicClient": args.public_client.unwrap_or(false),
            "serviceAccountsEnabled": args.service_accounts_enabled.unwrap_or(false),
            "enabled": args.enabled.unwrap_or(true),
        });
        let path = format!("/admin/realms/{}/clients", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let id = payload
            .as_object()
            .and_then(|obj| obj.get("id"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        Ok(CallToolResult::structured(json!({ "id": id })))
    }

    /// Update client fields.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes client configuration.
    #[tool(name = "clients.update", description = "Update client fields.")]
    pub(crate) async fn clients_update(
        &self,
        Parameters(args): Parameters<ClientsUpdateArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        if let Some(id) = &args.id {
            validate_uuid(id, "id")?;
        }
        if let Some(client_id) = &args.client_id {
            validate_no_path_traversal(client_id, "client_id")?;
        }

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

        let mut updates = serde_json::Map::new();
        if let Some(name) = args.name {
            validate_no_path_traversal(&name, "name")?;
            updates.insert("name".to_string(), json!(name));
        }
        if let Some(description) = args.description {
            validate_no_path_traversal(&description, "description")?;
            updates.insert("description".to_string(), json!(description));
        }
        if let Some(enabled) = args.enabled {
            updates.insert("enabled".to_string(), json!(enabled));
        }
        if let Some(public_client) = args.public_client {
            updates.insert("publicClient".to_string(), json!(public_client));
        }
        if let Some(service_accounts_enabled) = args.service_accounts_enabled {
            updates.insert(
                "serviceAccountsEnabled".to_string(),
                json!(service_accounts_enabled),
            );
        }
        if let Some(standard_flow_enabled) = args.standard_flow_enabled {
            updates.insert(
                "standardFlowEnabled".to_string(),
                json!(standard_flow_enabled),
            );
        }
        if let Some(direct_access_grants_enabled) = args.direct_access_grants_enabled {
            updates.insert(
                "directAccessGrantsEnabled".to_string(),
                json!(direct_access_grants_enabled),
            );
        }
        if let Some(consent_required) = args.consent_required {
            updates.insert("consentRequired".to_string(), json!(consent_required));
        }
        if let Some(bearer_only) = args.bearer_only {
            updates.insert("bearerOnly".to_string(), json!(bearer_only));
        }

        if updates.is_empty() {
            return Ok(tool_error(
                "clients.no_updates",
                "No update fields provided.",
                &ctx.request_id,
            ));
        }

        let path = format!("/admin/realms/{}/clients/{}", args.realm, client_id);
        if let Err(err) = self
            .gateway
            .request_json(
                &ctx,
                Method::PUT,
                &path,
                Vec::new(),
                Some(serde_json::Value::Object(updates)),
            )
            .await
        {
            match err {
                crate::gateway::GatewayError::Upstream { status, .. } if status == 404 => {
                    return Ok(tool_error(
                        "clients.not_found",
                        "Client not found.",
                        &ctx.request_id,
                    ));
                }
                crate::gateway::GatewayError::Upstream { status, summary } => {
                    return Err(crate::McpError::internal_error(
                        "gateway request failed",
                        Some(json!({
                            "upstream_status": status,
                            "upstream_error": summary,
                        })),
                    ));
                }
                _ => {
                    return Err(crate::McpError::internal_error(
                        "gateway request failed",
                        None,
                    ));
                }
            }
        }

        Ok(CallToolResult::structured(
            json!({ "updated": true, "id": client_id }),
        ))
    }

    /// Enable a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes enablement state.
    #[tool(name = "clients.enable", description = "Enable a client.")]
    pub(crate) async fn clients_enable(
        &self,
        Parameters(args): Parameters<ClientsToggleArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        if let Some(id) = &args.id {
            validate_uuid(id, "id")?;
        }
        if let Some(client_id) = &args.client_id {
            validate_no_path_traversal(client_id, "client_id")?;
        }

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
        let body = json!({ "enabled": true });
        if let Err(err) = self
            .gateway
            .request_json(&ctx, Method::PUT, &path, Vec::new(), Some(body))
            .await
        {
            match err {
                crate::gateway::GatewayError::Upstream { status, .. } if status == 404 => {
                    return Ok(tool_error(
                        "clients.not_found",
                        "Client not found.",
                        &ctx.request_id,
                    ));
                }
                crate::gateway::GatewayError::Upstream { status, summary } => {
                    return Err(crate::McpError::internal_error(
                        "gateway request failed",
                        Some(json!({
                            "upstream_status": status,
                            "upstream_error": summary,
                        })),
                    ));
                }
                _ => {
                    return Err(crate::McpError::internal_error(
                        "gateway request failed",
                        None,
                    ));
                }
            }
        }

        Ok(CallToolResult::structured(json!({
            "enabled": true,
            "id": client_id,
        })))
    }

    /// Disable a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes enablement state.
    #[tool(name = "clients.disable", description = "Disable a client.")]
    pub(crate) async fn clients_disable(
        &self,
        Parameters(args): Parameters<ClientsToggleArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        if let Some(id) = &args.id {
            validate_uuid(id, "id")?;
        }
        if let Some(client_id) = &args.client_id {
            validate_no_path_traversal(client_id, "client_id")?;
        }

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
        let body = json!({ "enabled": false });
        if let Err(err) = self
            .gateway
            .request_json(&ctx, Method::PUT, &path, Vec::new(), Some(body))
            .await
        {
            match err {
                crate::gateway::GatewayError::Upstream { status, .. } if status == 404 => {
                    return Ok(tool_error(
                        "clients.not_found",
                        "Client not found.",
                        &ctx.request_id,
                    ));
                }
                crate::gateway::GatewayError::Upstream { status, summary } => {
                    return Err(crate::McpError::internal_error(
                        "gateway request failed",
                        Some(json!({
                            "upstream_status": status,
                            "upstream_error": summary,
                        })),
                    ));
                }
                _ => {
                    return Err(crate::McpError::internal_error(
                        "gateway request failed",
                        None,
                    ));
                }
            }
        }

        Ok(CallToolResult::structured(json!({
            "enabled": false,
            "id": client_id,
        })))
    }

    /// Delete a client by id or clientId.
    ///
    /// # Security
    /// * **Destructive**: Gated by `keycloak-admin:clients:write`.
    #[tool(
        name = "clients.delete",
        description = "Delete a client by id or clientId."
    )]
    pub(crate) async fn clients_delete(
        &self,
        Parameters(args): Parameters<ClientsDeleteArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_realm_name(&args.realm)?;
        if let Some(id) = &args.id {
            validate_uuid(id, "id")?;
        }
        if let Some(client_id) = &args.client_id {
            validate_no_path_traversal(client_id, "client_id")?;
        }

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
        if let Err(err) = self
            .gateway
            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
            .await
        {
            match err {
                crate::gateway::GatewayError::Upstream { status, .. } if status == 404 => {
                    return Ok(tool_error(
                        "clients.not_found",
                        "Client not found.",
                        &ctx.request_id,
                    ));
                }
                crate::gateway::GatewayError::Upstream { status, summary } => {
                    return Err(crate::McpError::internal_error(
                        "gateway request failed",
                        Some(json!({
                            "upstream_status": status,
                            "upstream_error": summary,
                        })),
                    ));
                }
                _ => {
                    return Err(crate::McpError::internal_error(
                        "gateway request failed",
                        None,
                    ));
                }
            }
        }

        Ok(CallToolResult::structured(json!({ "deleted": true })))
    }

    /// Create a hardened introspection-only client and return its secret.
    ///
    /// # Security
    /// * **Credentials**: Returns a sensitive `client_secret`.
    /// * **Isolation**: Only creates clients with zero login capabilities (introspection only).
    #[tool(
        name = "clients.introspection.create",
        description = "Create a hardened introspection-only client (confirm=true)."
    )]
    pub(crate) async fn clients_introspection_create(
        &self,
        Parameters(args): Parameters<ClientsIntrospectionCreateArgs>,
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
                "confirm=true is required to create introspection clients.",
                &ctx.request_id,
            ));
        }

        let body = json!({
            "clientId": args.client_id,
            "name": args.name,
            "protocol": "openid-connect",
            "publicClient": false,
            "serviceAccountsEnabled": false,
            "standardFlowEnabled": false,
            "directAccessGrantsEnabled": false,
            "enabled": true,
        });
        let path = format!("/admin/realms/{}/clients", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::POST, &path, Vec::new(), Some(body))
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let id = payload
            .get("id")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());
        let id = match id {
            Some(value) => value,
            None => {
                return Ok(tool_error(
                    "clients.no_id",
                    "Client created but no id returned.",
                    &ctx.request_id,
                ))
            }
        };

        let secret_path = format!("/admin/realms/{}/clients/{}/client-secret", args.realm, id);
        let secret_payload = self
            .gateway
            .request_json(&ctx, Method::POST, &secret_path, Vec::new(), None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;
        let secret = secret_payload
            .get("value")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());

        Ok(CallToolResult::structured(
            json!({ "id": id, "secret": secret }),
        ))
    }

    /// Update multiple clients in a single call.
    ///
    /// # Security
    /// * **Bulk Write**: Requires `confirm=true` to prevent accidental mass updates.
    #[tool(
        name = "clients.bulk_update",
        description = "Update multiple clients in a single call (confirm=true)."
    )]
    pub(crate) async fn clients_bulk_update(
        &self,
        Parameters(args): Parameters<ClientsBulkUpdateArgs>,
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
        if !args.confirm {
            return Ok(tool_error(
                "clients.confirm_required",
                "confirm=true is required to bulk update clients.",
                &ctx.request_id,
            ));
        }
        if args.updates.is_empty() {
            return Ok(tool_error(
                "clients.invalid_input",
                "updates must include at least one entry.",
                &ctx.request_id,
            ));
        }
        if args.updates.len() > 50 {
            return Ok(tool_error(
                "clients.too_many",
                "updates must include at most 50 entries.",
                &ctx.request_id,
            ));
        }

        let dry_run = args.dry_run.unwrap_or(false);
        let mut updated = Vec::new();
        let mut skipped = Vec::new();
        let mut errors = Vec::new();

        for update in args.updates.iter() {
            if update.id.is_none() && update.client_id.is_none() {
                errors.push(BulkUpdateError {
                    client: "unknown".to_string(),
                    error: "id or client_id is required.".to_string(),
                });
                continue;
            }

            let label = update
                .client_id
                .clone()
                .or_else(|| update.id.clone())
                .unwrap_or_else(|| "unknown".to_string());
            let client_id = resolve_client_id(
                self,
                &ctx,
                &args.realm,
                update.id.as_ref(),
                update.client_id.as_ref(),
            )
            .await;
            let client_id = match client_id {
                Ok(value) => value,
                Err(err) => {
                    errors.push(BulkUpdateError {
                        client: label,
                        error: err.to_string(),
                    });
                    continue;
                }
            };
            let client_id = match client_id {
                Some(id) => id,
                None => {
                    errors.push(BulkUpdateError {
                        client: label,
                        error: "Client not found.".to_string(),
                    });
                    continue;
                }
            };

            let mut updates = serde_json::Map::new();
            if let Some(name) = update.name.clone() {
                updates.insert("name".to_string(), json!(name));
            }
            if let Some(description) = update.description.clone() {
                updates.insert("description".to_string(), json!(description));
            }
            if let Some(enabled) = update.enabled {
                updates.insert("enabled".to_string(), json!(enabled));
            }
            if let Some(public_client) = update.public_client {
                updates.insert("publicClient".to_string(), json!(public_client));
            }
            if let Some(service_accounts_enabled) = update.service_accounts_enabled {
                updates.insert(
                    "serviceAccountsEnabled".to_string(),
                    json!(service_accounts_enabled),
                );
            }
            if let Some(standard_flow_enabled) = update.standard_flow_enabled {
                updates.insert(
                    "standardFlowEnabled".to_string(),
                    json!(standard_flow_enabled),
                );
            }
            if let Some(direct_access_grants_enabled) = update.direct_access_grants_enabled {
                updates.insert(
                    "directAccessGrantsEnabled".to_string(),
                    json!(direct_access_grants_enabled),
                );
            }
            if let Some(consent_required) = update.consent_required {
                updates.insert("consentRequired".to_string(), json!(consent_required));
            }
            if let Some(bearer_only) = update.bearer_only {
                updates.insert("bearerOnly".to_string(), json!(bearer_only));
            }

            if updates.is_empty() {
                skipped.push(client_id);
                continue;
            }

            if !dry_run {
                let path = format!("/admin/realms/{}/clients/{}", args.realm, client_id);
                if let Err(err) = self
                    .gateway
                    .request_json(
                        &ctx,
                        Method::PUT,
                        &path,
                        Vec::new(),
                        Some(serde_json::Value::Object(updates)),
                    )
                    .await
                {
                    errors.push(BulkUpdateError {
                        client: client_id,
                        error: match err {
                            crate::gateway::GatewayError::Upstream { status, summary } => {
                                summary.unwrap_or_else(|| format!("upstream_status={status}"))
                            }
                            _ => "gateway request failed".to_string(),
                        },
                    });
                    continue;
                }
            }
            updated.push(client_id);
        }

        Ok(CallToolResult::structured(json!(BulkUpdateSummary {
            updated,
            skipped,
            errors,
            dry_run,
        })))
    }

    /// Disable or delete clients that match the provided filters.
    ///
    /// # Security
    /// * **Pruning**: Destructive action requiring `confirm=true`.
    /// * **Dry Run**: Defaults to `dry_run=true` to safely preview matches.
    #[tool(
        name = "clients.prune",
        description = "Disable or delete clients matching the provided filters (confirm=true)."
    )]
    pub(crate) async fn clients_prune(
        &self,
        Parameters(args): Parameters<ClientsPruneArgs>,
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
        if !args.confirm {
            return Ok(tool_error(
                "clients.confirm_required",
                "confirm=true is required to prune clients.",
                &ctx.request_id,
            ));
        }

        let has_filter = args.search.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
            || args.name.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
            || args
                .client_id_prefix
                .as_ref()
                .map(|v| !v.is_empty())
                .unwrap_or(false)
            || args
                .client_id_pattern
                .as_ref()
                .map(|v| !v.is_empty())
                .unwrap_or(false);
        if !has_filter {
            return Ok(tool_error(
                "clients.invalid_input",
                "At least one filter (search, name, client_id_prefix, client_id_pattern) is required.",
                &ctx.request_id,
            ));
        }

        let regex: Option<Regex> = match args.client_id_pattern.as_ref() {
            Some(pattern) => match Regex::new(pattern) {
                Ok(value) => Some(value),
                Err(_) => {
                    return Ok(tool_error(
                        "clients.invalid_pattern",
                        "Invalid client_id_pattern; must be a valid regex.",
                        &ctx.request_id,
                    ))
                }
            },
            None => None,
        };

        let exclude: HashSet<String> = args
            .exclude_client_ids
            .unwrap_or_default()
            .into_iter()
            .collect();
        let max = args.max.unwrap_or(200);
        if max == 0 || max > 200 {
            return Ok(tool_error(
                "clients.invalid_input",
                "max must be between 1 and 200.",
                &ctx.request_id,
            ));
        }
        let limit_value = args.limit.unwrap_or(50);
        if limit_value == 0 || limit_value > 200 {
            return Ok(tool_error(
                "clients.invalid_input",
                "limit must be between 1 and 200.",
                &ctx.request_id,
            ));
        }
        let limit = limit_value as usize;
        let dry_run = args.dry_run.unwrap_or(true);
        let action = args.action.unwrap_or(ClientsPruneAction::Disable);

        let mut query = Vec::new();
        query.push(("max".to_string(), max.to_string()));

        let path = format!("/admin/realms/{}/clients", args.realm);
        let payload = self
            .gateway
            .request_json(&ctx, Method::GET, &path, query, None)
            .await
            .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

        let clients: Vec<ClientRepresentation> = match payload {
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<ClientRepresentation>(item).ok())
                .collect(),
            _ => Vec::new(),
        };

        let search_term = args.search.map(|value| value.to_lowercase());
        let matched: Vec<String> = clients
            .iter()
            .filter(|client| {
                let client_id = match client.client_id.as_ref() {
                    Some(value) => value,
                    None => return false,
                };
                if exclude.contains(client_id) {
                    return false;
                }
                if let Some(term) = search_term.as_ref() {
                    let haystack =
                        format!("{} {}", client_id, client.name.as_deref().unwrap_or(""))
                            .to_lowercase();
                    if !haystack.contains(term) {
                        return false;
                    }
                }
                if let Some(name) = args.name.as_ref() {
                    if client
                        .name
                        .as_ref()
                        .map(|value| value != name)
                        .unwrap_or(true)
                    {
                        return false;
                    }
                }
                if let Some(prefix) = args.client_id_prefix.as_ref() {
                    if !client_id.starts_with(prefix) {
                        return false;
                    }
                }
                if let Some(regex) = regex.as_ref() {
                    if !regex.is_match(client_id) {
                        return false;
                    }
                }
                true
            })
            .filter_map(|client| client.id.clone())
            .collect();

        let limited: Vec<String> = matched.iter().take(limit).cloned().collect();
        let mut processed = Vec::new();
        let mut skipped = Vec::new();

        if dry_run {
            skipped.extend(limited.iter().cloned());
        } else {
            for client_id in limited.iter() {
                match action {
                    ClientsPruneAction::Delete => {
                        let path = format!("/admin/realms/{}/clients/{}", args.realm, client_id);
                        self.gateway
                            .request_json(&ctx, Method::DELETE, &path, Vec::new(), None)
                            .await
                            .map_err(|_| {
                                crate::McpError::internal_error("gateway request failed", None)
                            })?;
                    }
                    ClientsPruneAction::Disable => {
                        let path = format!("/admin/realms/{}/clients/{}", args.realm, client_id);
                        let body = json!({ "enabled": false });
                        self.gateway
                            .request_json(&ctx, Method::PUT, &path, Vec::new(), Some(body))
                            .await
                            .map_err(|_| {
                                crate::McpError::internal_error("gateway request failed", None)
                            })?;
                    }
                }
                processed.push(client_id.to_string());
            }
        }

        Ok(CallToolResult::structured(json!(PruneSummary {
            dry_run,
            action: match action {
                ClientsPruneAction::Delete => "delete".to_string(),
                ClientsPruneAction::Disable => "disable".to_string(),
            },
            matched,
            processed,
            skipped,
        })))
    }
}
