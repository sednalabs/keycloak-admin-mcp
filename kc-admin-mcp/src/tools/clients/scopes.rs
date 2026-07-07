use super::*;
use mcp_toolkit_core::response_contract::MutationOutcome;

#[derive(Debug, serde::Serialize, JsonSchema)]
struct ScopeBindingCheckResult {
    scope: String,
    scope_exists: bool,
    in_default: bool,
    in_optional: bool,
    currently_bound: bool,
    effective_scope_names: Vec<String>,
    missing_scope_hint: Option<serde_json::Value>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct ScopeMutationSummary {
    outcome: String,
    client: String,
    changed: bool,
    requested_state: String,
    scope_kind: String,
    requested_scope_ids: Vec<String>,
    already_bound: Vec<String>,
    to_add: Vec<String>,
    to_remove: Vec<String>,
    will_apply: bool,
    dry_run: bool,
}

#[derive(Debug)]
struct ScopeMutationPlan {
    requested: Vec<String>,
    already_bound: Vec<String>,
    added: Vec<String>,
    removed: Vec<String>,
}

#[derive(Copy, Clone)]
enum ScopeMutationAction {
    Add,
    Remove,
}

fn scope_kind_label(kind: ScopeKind) -> &'static str {
    match kind {
        ScopeKind::Default => "default",
        ScopeKind::Optional => "optional",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_string()).collect()
    }

    #[test]
    fn repeated_attach_reports_already_bound_without_changes() {
        let existing = values(&["scope-a"]);
        let requested = values(&["scope-a"]);
        let plan = scope_add_plan(&existing, &requested);
        let outcome = mutation_outcome(
            &plan.added,
            &plan.removed,
            false,
            MutationOutcome::AlreadyBound,
        );
        let summary = scope_mutation_summary(
            outcome,
            "client-uuid",
            "bound",
            "default",
            plan.requested,
            plan.already_bound,
            plan.added,
            plan.removed,
            false,
        );

        assert_eq!(summary.outcome, "already_bound");
        assert_eq!(summary.client, "client-uuid");
        assert_eq!(summary.requested_state, "bound");
        assert!(!summary.changed);
        assert!(!summary.will_apply);
    }

    #[test]
    fn repeated_remove_reports_already_unbound_without_changes() {
        let existing = Vec::new();
        let requested = values(&["scope-a"]);
        let plan = scope_remove_plan(&existing, &requested);
        let outcome = mutation_outcome(
            &plan.added,
            &plan.removed,
            false,
            MutationOutcome::AlreadyUnbound,
        );
        let summary = scope_mutation_summary(
            outcome,
            "client-uuid",
            "unbound",
            "optional",
            plan.requested,
            plan.already_bound,
            plan.added,
            plan.removed,
            false,
        );

        assert_eq!(summary.outcome, "already_unbound");
        assert_eq!(summary.requested_state, "unbound");
        assert!(!summary.changed);
        assert!(!summary.will_apply);
    }

    #[test]
    fn dry_run_attach_reports_preview_without_apply() {
        let existing = Vec::new();
        let requested = values(&["scope-a"]);
        let plan = scope_add_plan(&existing, &requested);
        let outcome = mutation_outcome(
            &plan.added,
            &plan.removed,
            true,
            MutationOutcome::AlreadyBound,
        );
        let summary = scope_mutation_summary(
            outcome,
            "client-uuid",
            "bound",
            "default",
            plan.requested,
            plan.already_bound,
            plan.added,
            plan.removed,
            true,
        );

        assert_eq!(summary.outcome, "would_add");
        assert!(summary.changed);
        assert!(!summary.will_apply);
        assert!(summary.dry_run);
    }
}

fn scope_kind_path(kind: ScopeKind) -> &'static str {
    match kind {
        ScopeKind::Default => "default-client-scopes",
        ScopeKind::Optional => "optional-client-scopes",
    }
}

fn normalize_scope_id_list(mut values: Vec<String>) -> Vec<String> {
    values.sort_unstable();
    values.dedup();
    values
}

fn scope_add_plan(existing: &[String], requested: &[String]) -> ScopeMutationPlan {
    let existing_set: HashSet<&str> = existing.iter().map(String::as_str).collect();

    let requested = normalize_scope_id_list(requested.to_vec());

    let already_bound: Vec<String> = requested
        .iter()
        .filter(|id| existing_set.contains(id.as_str()))
        .cloned()
        .collect();
    let mut added: Vec<String> = requested
        .iter()
        .filter(|id| !existing_set.contains(id.as_str()))
        .cloned()
        .collect();
    added = normalize_scope_id_list(added);

    ScopeMutationPlan {
        requested,
        already_bound,
        added,
        removed: Vec::new(),
    }
}

fn scope_remove_plan(existing: &[String], requested: &[String]) -> ScopeMutationPlan {
    let existing_set: HashSet<&str> = existing.iter().map(String::as_str).collect();

    let requested = normalize_scope_id_list(requested.to_vec());

    let mut to_remove: Vec<String> = requested
        .iter()
        .filter(|id| existing_set.contains(id.as_str()))
        .cloned()
        .collect();
    to_remove = normalize_scope_id_list(to_remove);

    let already_bound: Vec<String> = requested
        .iter()
        .filter(|id| !existing_set.contains(id.as_str()))
        .cloned()
        .collect();

    ScopeMutationPlan {
        requested,
        already_bound,
        added: Vec::new(),
        removed: to_remove,
    }
}

fn scope_replace_plan(existing: &[String], desired: &[String]) -> ScopeMutationPlan {
    let existing_set: HashSet<&str> = existing.iter().map(String::as_str).collect();
    let desired_set: HashSet<&str> = desired.iter().map(String::as_str).collect();

    let requested = normalize_scope_id_list(desired.to_vec());

    let mut already_bound: Vec<String> = existing
        .iter()
        .filter(|id| desired_set.contains(id.as_str()))
        .cloned()
        .collect();
    already_bound = normalize_scope_id_list(already_bound);

    let mut to_add: Vec<String> = desired_set
        .difference(&existing_set)
        .map(|value| value.to_string())
        .collect();
    to_add = normalize_scope_id_list(to_add);

    let mut to_remove: Vec<String> = existing_set
        .difference(&desired_set)
        .map(|value| value.to_string())
        .collect();
    to_remove = normalize_scope_id_list(to_remove);

    ScopeMutationPlan {
        requested,
        already_bound,
        added: to_add,
        removed: to_remove,
    }
}

fn scope_binding_path(realm: &str, client_id: &str, kind: ScopeKind, scope_id: &str) -> String {
    format!(
        "/admin/realms/{}/clients/{}/{}/{}",
        realm,
        client_id,
        scope_kind_path(kind),
        scope_id
    )
}

fn validate_scope_client_inputs(
    realm: &str,
    id: Option<&String>,
    client_id: Option<&String>,
) -> Result<(), crate::McpError> {
    validate_realm_name(realm)?;
    if let Some(id) = id {
        validate_uuid(id, "id")?;
    }
    if let Some(client_id) = client_id {
        validate_no_path_traversal(client_id, "client_id")?;
    }
    Ok(())
}

async fn existing_client_scopes(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    client_id: &str,
    kind: ScopeKind,
) -> Result<Vec<String>, crate::McpError> {
    let existing = list_client_scopes(mcp, ctx, realm, client_id, kind).await?;
    let mut ids: Vec<String> = existing.into_iter().filter_map(|scope| scope.id).collect();
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

async fn apply_scope_mutation(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    client_id: &str,
    kind: ScopeKind,
    scope_id: &str,
    action: ScopeMutationAction,
    dry_run: bool,
) -> Result<(), crate::McpError> {
    if dry_run {
        return Ok(());
    }

    let path = scope_binding_path(realm, client_id, kind, scope_id);
    let method = match action {
        ScopeMutationAction::Add => Method::PUT,
        ScopeMutationAction::Remove => Method::DELETE,
    };

    mcp.gateway
        .request_json(ctx, method, &path, Vec::new(), None)
        .await
        .map_err(|_| crate::McpError::internal_error("gateway request failed", None))?;

    Ok(())
}

async fn resolve_scope_binding(
    mcp: &KcAdminMcp,
    ctx: &crate::auth::AuthContext,
    realm: &str,
    client_id: &str,
    scope_token: &str,
) -> Result<ScopeBindingCheckResult, crate::McpError> {
    let normalized_scope = scope_token.trim();
    let scope_token = normalized_scope.to_string();
    let scope_token_hint = scope_token.clone();

    let lookup = load_client_scope_lookup(mcp, ctx, realm).await?;
    let maybe_scope_id = resolve_scope_lookup(&scope_token, &lookup);

    let default_scopes = list_client_scopes(mcp, ctx, realm, client_id, ScopeKind::Default).await?;
    let optional_scopes =
        list_client_scopes(mcp, ctx, realm, client_id, ScopeKind::Optional).await?;

    let mut effective_scope_names: Vec<String> = default_scopes
        .iter()
        .chain(optional_scopes.iter())
        .filter_map(|scope| scope.name.clone())
        .collect();
    effective_scope_names.sort_unstable();
    effective_scope_names.dedup();

    let default_ids: HashSet<&str> = default_scopes
        .iter()
        .filter_map(|scope| scope.id.as_deref())
        .collect();
    let optional_ids: HashSet<&str> = optional_scopes
        .iter()
        .filter_map(|scope| scope.id.as_deref())
        .collect();

    let in_default = maybe_scope_id
        .as_ref()
        .is_some_and(|id| default_ids.contains(id.as_str()));
    let in_optional = maybe_scope_id
        .as_ref()
        .is_some_and(|id| optional_ids.contains(id.as_str()));
    let currently_bound = in_default || in_optional;

    Ok(ScopeBindingCheckResult {
        scope: scope_token,
        scope_exists: maybe_scope_id.is_some(),
        in_default,
        in_optional,
        currently_bound,
        effective_scope_names,
        missing_scope_hint: if maybe_scope_id.is_none() {
            Some(json!({
                "code": "scope.missing",
                "next_action": "clients.scope.ensure",
                "query": scope_token_hint,
                "remedy": "resolve scope id/name via clients.scopes.list, then call clients.scope.ensure with ensure=true",
            }))
        } else {
            None
        },
    })
}

fn mutation_outcome(
    to_add: &[String],
    to_remove: &[String],
    dry_run: bool,
    no_change_default: MutationOutcome,
) -> MutationOutcome {
    if to_add.is_empty() && to_remove.is_empty() {
        return no_change_default;
    }

    if dry_run {
        if !to_add.is_empty() && !to_remove.is_empty() {
            MutationOutcome::WouldUpdate
        } else if !to_add.is_empty() {
            MutationOutcome::WouldAdd
        } else {
            MutationOutcome::WouldRemove
        }
    } else if !to_add.is_empty() && !to_remove.is_empty() {
        MutationOutcome::Updated
    } else if !to_add.is_empty() {
        MutationOutcome::Added
    } else {
        MutationOutcome::Removed
    }
}

fn scope_mutation_summary(
    outcome: MutationOutcome,
    client: &str,
    requested_state: &str,
    scope_kind: &str,
    requested_scope_ids: Vec<String>,
    already_bound: Vec<String>,
    to_add: Vec<String>,
    to_remove: Vec<String>,
    dry_run: bool,
) -> ScopeMutationSummary {
    let changed = !to_add.is_empty() || !to_remove.is_empty();
    ScopeMutationSummary {
        outcome: outcome.as_str().to_string(),
        client: client.to_string(),
        changed,
        requested_state: requested_state.to_string(),
        scope_kind: scope_kind.to_string(),
        requested_scope_ids,
        already_bound,
        to_add,
        to_remove,
        will_apply: !dry_run && changed,
        dry_run,
    }
}

#[mcp_toolkit_core::rmcp::tool_router(router = tool_router_clients_scopes, vis = "pub")]
impl KcAdminMcp {
    /// List default client scopes for a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
    #[tool(
        name = "clients.default_scopes",
        description = "List default client scopes."
    )]
    pub(crate) async fn clients_default_scopes(
        &self,
        Parameters(args): Parameters<ClientsScopesArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_scope_client_inputs(&args.realm, args.id.as_ref(), args.client_id.as_ref())?;
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
            "/admin/realms/{}/clients/{}/default-client-scopes",
            args.realm, client_id
        );
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

    /// List optional client scopes for a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
    #[tool(
        name = "clients.optional_scopes",
        description = "List optional client scopes."
    )]
    pub(crate) async fn clients_optional_scopes(
        &self,
        Parameters(args): Parameters<ClientsScopesArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_scope_client_inputs(&args.realm, args.id.as_ref(), args.client_id.as_ref())?;
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
            "/admin/realms/{}/clients/{}/optional-client-scopes",
            args.realm, client_id
        );
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

    /// Attach one or more default client scopes to a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes scope mappings.
    #[tool(
        name = "clients.default_scopes.add",
        description = "Attach one or more default client scopes to a client."
    )]
    pub(crate) async fn clients_default_scopes_add(
        &self,
        Parameters(args): Parameters<ClientsScopesMutationArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_scope_client_inputs(&args.realm, args.id.as_ref(), args.client_id.as_ref())?;
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

        let resolved = resolve_scope_ids(self, &ctx, &args.realm, &args).await?;
        if !resolved.missing_names.is_empty() {
            return Ok(tool_error(
                "client_scopes.not_found",
                &format!(
                    "Client scopes not found: {}",
                    resolved.missing_names.join(", ")
                ),
                &ctx.request_id,
            ));
        }
        if resolved.ids.is_empty() {
            return Ok(tool_error(
                "client_scopes.none",
                "No client scopes resolved.",
                &ctx.request_id,
            ));
        }

        let existing_ids =
            existing_client_scopes(self, &ctx, &args.realm, &client_id, ScopeKind::Default).await?;
        let plan = scope_add_plan(&existing_ids, &resolved.ids);

        for scope_id in plan.added.iter() {
            validate_no_path_traversal(scope_id, "scope_id")?;
            apply_scope_mutation(
                self,
                &ctx,
                &args.realm,
                &client_id,
                ScopeKind::Default,
                scope_id,
                ScopeMutationAction::Add,
                args.dry_run.unwrap_or(false),
            )
            .await?;
        }

        let dry_run = args.dry_run.unwrap_or(false);
        Ok(CallToolResult::structured(json!(scope_mutation_summary(
            mutation_outcome(
                &plan.added,
                &plan.removed,
                dry_run,
                MutationOutcome::AlreadyBound,
            ),
            &client_id,
            "bound",
            scope_kind_label(ScopeKind::Default),
            plan.requested,
            plan.already_bound,
            plan.added,
            plan.removed,
            dry_run,
        ))))
    }

    /// Remove one or more default client scopes from a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive.
    #[tool(
        name = "clients.default_scopes.delete",
        description = "Remove one or more default client scopes from a client."
    )]
    pub(crate) async fn clients_default_scopes_delete(
        &self,
        Parameters(args): Parameters<ClientsScopesMutationArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_scope_client_inputs(&args.realm, args.id.as_ref(), args.client_id.as_ref())?;
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

        let resolved = resolve_scope_ids(self, &ctx, &args.realm, &args).await?;
        if !resolved.missing_names.is_empty() {
            return Ok(tool_error(
                "client_scopes.not_found",
                &format!(
                    "Client scopes not found: {}",
                    resolved.missing_names.join(", ")
                ),
                &ctx.request_id,
            ));
        }
        if resolved.ids.is_empty() {
            return Ok(tool_error(
                "client_scopes.none",
                "No client scopes resolved.",
                &ctx.request_id,
            ));
        }

        let existing_ids =
            existing_client_scopes(self, &ctx, &args.realm, &client_id, ScopeKind::Default).await?;
        let plan = scope_remove_plan(&existing_ids, &resolved.ids);

        for scope_id in plan.removed.iter() {
            validate_no_path_traversal(scope_id, "scope_id")?;
            apply_scope_mutation(
                self,
                &ctx,
                &args.realm,
                &client_id,
                ScopeKind::Default,
                scope_id,
                ScopeMutationAction::Remove,
                args.dry_run.unwrap_or(false),
            )
            .await?;
        }

        let dry_run = args.dry_run.unwrap_or(false);
        Ok(CallToolResult::structured(json!(scope_mutation_summary(
            mutation_outcome(
                &plan.added,
                &plan.removed,
                dry_run,
                MutationOutcome::AlreadyUnbound,
            ),
            &client_id,
            "unbound",
            scope_kind_label(ScopeKind::Default),
            plan.requested,
            plan.already_bound,
            plan.added,
            plan.removed,
            dry_run,
        ))))
    }

    /// Attach one or more optional client scopes to a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes scope mappings.
    #[tool(
        name = "clients.optional_scopes.add",
        description = "Attach one or more optional client scopes to a client."
    )]
    pub(crate) async fn clients_optional_scopes_add(
        &self,
        Parameters(args): Parameters<ClientsScopesMutationArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_scope_client_inputs(&args.realm, args.id.as_ref(), args.client_id.as_ref())?;
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

        let resolved = resolve_scope_ids(self, &ctx, &args.realm, &args).await?;
        if !resolved.missing_names.is_empty() {
            return Ok(tool_error(
                "client_scopes.not_found",
                &format!(
                    "Client scopes not found: {}",
                    resolved.missing_names.join(", ")
                ),
                &ctx.request_id,
            ));
        }
        if resolved.ids.is_empty() {
            return Ok(tool_error(
                "client_scopes.none",
                "No client scopes resolved.",
                &ctx.request_id,
            ));
        }

        let existing_ids =
            existing_client_scopes(self, &ctx, &args.realm, &client_id, ScopeKind::Optional)
                .await?;
        let plan = scope_add_plan(&existing_ids, &resolved.ids);

        for scope_id in plan.added.iter() {
            validate_no_path_traversal(scope_id, "scope_id")?;
            apply_scope_mutation(
                self,
                &ctx,
                &args.realm,
                &client_id,
                ScopeKind::Optional,
                scope_id,
                ScopeMutationAction::Add,
                args.dry_run.unwrap_or(false),
            )
            .await?;
        }

        let dry_run = args.dry_run.unwrap_or(false);
        Ok(CallToolResult::structured(json!(scope_mutation_summary(
            mutation_outcome(
                &plan.added,
                &plan.removed,
                dry_run,
                MutationOutcome::AlreadyBound,
            ),
            &client_id,
            "bound",
            scope_kind_label(ScopeKind::Optional),
            plan.requested,
            plan.already_bound,
            plan.added,
            plan.removed,
            dry_run,
        ))))
    }

    /// Remove one or more optional client scopes from a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive.
    #[tool(
        name = "clients.optional_scopes.delete",
        description = "Remove one or more optional client scopes from a client."
    )]
    pub(crate) async fn clients_optional_scopes_delete(
        &self,
        Parameters(args): Parameters<ClientsScopesMutationArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_scope_client_inputs(&args.realm, args.id.as_ref(), args.client_id.as_ref())?;
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

        let resolved = resolve_scope_ids(self, &ctx, &args.realm, &args).await?;
        if !resolved.missing_names.is_empty() {
            return Ok(tool_error(
                "client_scopes.not_found",
                &format!(
                    "Client scopes not found: {}",
                    resolved.missing_names.join(", ")
                ),
                &ctx.request_id,
            ));
        }
        if resolved.ids.is_empty() {
            return Ok(tool_error(
                "client_scopes.none",
                "No client scopes resolved.",
                &ctx.request_id,
            ));
        }

        let existing_ids =
            existing_client_scopes(self, &ctx, &args.realm, &client_id, ScopeKind::Optional)
                .await?;
        let plan = scope_remove_plan(&existing_ids, &resolved.ids);

        for scope_id in plan.removed.iter() {
            validate_no_path_traversal(scope_id, "scope_id")?;
            apply_scope_mutation(
                self,
                &ctx,
                &args.realm,
                &client_id,
                ScopeKind::Optional,
                scope_id,
                ScopeMutationAction::Remove,
                args.dry_run.unwrap_or(false),
            )
            .await?;
        }

        let dry_run = args.dry_run.unwrap_or(false);
        Ok(CallToolResult::structured(json!(scope_mutation_summary(
            mutation_outcome(
                &plan.added,
                &plan.removed,
                dry_run,
                MutationOutcome::AlreadyUnbound,
            ),
            &client_id,
            "unbound",
            scope_kind_label(ScopeKind::Optional),
            plan.requested,
            plan.already_bound,
            plan.added,
            plan.removed,
            dry_run,
        ))))
    }

    /// Check whether a scope is currently bound to a client's default or optional scopes.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:read` (configurable); safety: read-only.
    #[tool(
        name = "clients.scope.binding",
        description = "Check whether a scope is bound to a client (default or optional)."
    )]
    pub(crate) async fn clients_scope_binding(
        &self,
        Parameters(args): Parameters<ClientsScopeBindingArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_scope_client_inputs(&args.realm, args.id.as_ref(), args.client_id.as_ref())?;
        let scope = args.scope.trim();
        if scope.is_empty() {
            return Ok(tool_error(
                "clients.invalid_input",
                "scope is required.",
                "req-scope-binding",
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

        let binding = resolve_scope_binding(self, &ctx, &args.realm, &client_id, scope).await?;
        Ok(CallToolResult::structured(json!(binding)))
    }

    /// Ensure a scope is bound or unbound for a client.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: writes scope mappings.
    #[tool(
        name = "clients.scope.ensure",
        description = "Ensure a scope is bound (ensure=true) or unbound (ensure=false) for a client."
    )]
    pub(crate) async fn clients_scope_ensure(
        &self,
        Parameters(args): Parameters<ClientsScopeEnsureArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_scope_client_inputs(&args.realm, args.id.as_ref(), args.client_id.as_ref())?;
        let scope = args.scope.trim();
        if scope.is_empty() {
            return Ok(tool_error(
                "clients.invalid_input",
                "scope is required.",
                "req-scope-ensure",
            ));
        }

        let ensure = args.ensure.unwrap_or(true);
        let dry_run = args.dry_run.unwrap_or(false);

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

        let lookup = load_client_scope_lookup(self, &ctx, &args.realm).await?;
        let resolved_scope_id = resolve_scope_lookup(scope, &lookup);

        let scope_id = match resolved_scope_id {
            Some(scope_id) => scope_id,
            None => {
                return Ok(tool_error(
                    "client_scopes.not_found",
                    "Client scope not found.",
                    &ctx.request_id,
                ));
            }
        };

        validate_no_path_traversal(&scope_id, "scope_id")?;

        let default_ids =
            existing_client_scopes(self, &ctx, &args.realm, &client_id, ScopeKind::Default).await?;
        let optional_ids =
            existing_client_scopes(self, &ctx, &args.realm, &client_id, ScopeKind::Optional)
                .await?;
        let in_default = default_ids.contains(&scope_id);
        let in_optional = optional_ids.contains(&scope_id);

        let mut already_bound = Vec::new();
        let mut to_add = Vec::new();
        let mut to_remove = Vec::new();
        let outcome;

        if ensure {
            if in_default || in_optional {
                already_bound.push(scope_id.clone());
                outcome = MutationOutcome::AlreadyBound;
            } else {
                to_add.push(scope_id.clone());
                if !dry_run {
                    apply_scope_mutation(
                        self,
                        &ctx,
                        &args.realm,
                        &client_id,
                        ScopeKind::Default,
                        &scope_id,
                        ScopeMutationAction::Add,
                        dry_run,
                    )
                    .await?;
                }
                outcome = if dry_run {
                    MutationOutcome::WouldAdd
                } else {
                    MutationOutcome::Added
                };
            }
        } else if !in_default && !in_optional {
            outcome = MutationOutcome::AlreadyUnbound;
        } else {
            if in_default {
                to_remove.push(scope_id.clone());
                if !dry_run {
                    apply_scope_mutation(
                        self,
                        &ctx,
                        &args.realm,
                        &client_id,
                        ScopeKind::Default,
                        &scope_id,
                        ScopeMutationAction::Remove,
                        dry_run,
                    )
                    .await?;
                }
            }
            if in_optional {
                to_remove.push(scope_id.clone());
                if !dry_run {
                    apply_scope_mutation(
                        self,
                        &ctx,
                        &args.realm,
                        &client_id,
                        ScopeKind::Optional,
                        &scope_id,
                        ScopeMutationAction::Remove,
                        dry_run,
                    )
                    .await?;
                }
            }
            to_remove.sort_unstable();
            to_remove.dedup();
            outcome = if dry_run {
                MutationOutcome::WouldRemove
            } else {
                MutationOutcome::Removed
            };
        }

        Ok(CallToolResult::structured(json!(scope_mutation_summary(
            outcome,
            &client_id,
            if ensure { "bound" } else { "unbound" },
            "default_or_optional",
            vec![scope_id],
            already_bound,
            to_add,
            to_remove,
            dry_run,
        ))))
    }

    /// Replace all default client scopes with the provided set.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive with confirm.
    #[tool(
        name = "clients.default_scopes.replace",
        description = "Replace all default client scopes with the provided set."
    )]
    pub(crate) async fn clients_default_scopes_replace(
        &self,
        Parameters(args): Parameters<ClientsScopesReplaceArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_scope_client_inputs(&args.realm, args.id.as_ref(), args.client_id.as_ref())?;
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
                "confirm=true is required to replace scopes.",
                &ctx.request_id,
            ));
        }

        let dry_run = args.dry_run.unwrap_or(false);
        let allow_empty = args.allow_empty.unwrap_or(false);
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

        let resolved = resolve_scope_ids(
            self,
            &ctx,
            &args.realm,
            &ClientsScopesMutationArgs {
                realm: args.realm.clone(),
                id: args.id.clone(),
                client_id: args.client_id.clone(),
                scope_id: args.scope_id.clone(),
                scope_ids: args.scope_ids.clone(),
                scope_name: args.scope_name.clone(),
                scope_names: args.scope_names.clone(),
                dry_run: Some(dry_run),
            },
        )
        .await?;

        if !resolved.missing_names.is_empty() {
            return Ok(tool_error(
                "client_scopes.not_found",
                &format!(
                    "Client scopes not found: {}",
                    resolved.missing_names.join(", ")
                ),
                &ctx.request_id,
            ));
        }
        if resolved.ids.is_empty() && !allow_empty {
            return Ok(tool_error_with_hint(
                "client_scopes.empty",
                "No client scopes resolved. Set allow_empty=true to clear all.",
                &ctx.request_id,
                "Set allow_empty=true if you intend to clear all scopes.",
            ));
        }

        let existing_ids =
            existing_client_scopes(self, &ctx, &args.realm, &client_id, ScopeKind::Default).await?;
        let plan = scope_replace_plan(&existing_ids, &resolved.ids);
        for scope_id in plan.removed.iter() {
            validate_no_path_traversal(scope_id, "scope_id")?;
            apply_scope_mutation(
                self,
                &ctx,
                &args.realm,
                &client_id,
                ScopeKind::Default,
                scope_id,
                ScopeMutationAction::Remove,
                dry_run,
            )
            .await?;
        }

        for scope_id in plan.added.iter() {
            validate_no_path_traversal(scope_id, "scope_id")?;
            apply_scope_mutation(
                self,
                &ctx,
                &args.realm,
                &client_id,
                ScopeKind::Default,
                scope_id,
                ScopeMutationAction::Add,
                dry_run,
            )
            .await?;
        }

        Ok(CallToolResult::structured(json!(scope_mutation_summary(
            mutation_outcome(
                &plan.added,
                &plan.removed,
                dry_run,
                MutationOutcome::AlreadyMatch,
            ),
            &client_id,
            "exact_match",
            scope_kind_label(ScopeKind::Default),
            plan.requested,
            plan.already_bound,
            plan.added,
            plan.removed,
            dry_run,
        ))))
    }

    /// Replace all optional client scopes with the provided set.
    /// Delegates to the Keycloak admin API via kc-admin-gateway.
    /// Required scopes: `keycloak-admin:clients:write` (configurable); safety: destructive with confirm.
    #[tool(
        name = "clients.optional_scopes.replace",
        description = "Replace all optional client scopes with the provided set."
    )]
    pub(crate) async fn clients_optional_scopes_replace(
        &self,
        Parameters(args): Parameters<ClientsScopesReplaceArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        validate_scope_client_inputs(&args.realm, args.id.as_ref(), args.client_id.as_ref())?;
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
                "confirm=true is required to replace scopes.",
                &ctx.request_id,
            ));
        }

        let dry_run = args.dry_run.unwrap_or(false);
        let allow_empty = args.allow_empty.unwrap_or(false);
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

        let resolved = resolve_scope_ids(
            self,
            &ctx,
            &args.realm,
            &ClientsScopesMutationArgs {
                realm: args.realm.clone(),
                id: args.id.clone(),
                client_id: args.client_id.clone(),
                scope_id: args.scope_id.clone(),
                scope_ids: args.scope_ids.clone(),
                scope_name: args.scope_name.clone(),
                scope_names: args.scope_names.clone(),
                dry_run: Some(dry_run),
            },
        )
        .await?;

        if !resolved.missing_names.is_empty() {
            return Ok(tool_error(
                "client_scopes.not_found",
                &format!(
                    "Client scopes not found: {}",
                    resolved.missing_names.join(", ")
                ),
                &ctx.request_id,
            ));
        }
        if resolved.ids.is_empty() && !allow_empty {
            return Ok(tool_error_with_hint(
                "client_scopes.empty",
                "No client scopes resolved. Set allow_empty=true to clear all.",
                &ctx.request_id,
                "Set allow_empty=true if you intend to clear all scopes.",
            ));
        }

        let existing_ids =
            existing_client_scopes(self, &ctx, &args.realm, &client_id, ScopeKind::Optional)
                .await?;
        let plan = scope_replace_plan(&existing_ids, &resolved.ids);
        for scope_id in plan.removed.iter() {
            validate_no_path_traversal(scope_id, "scope_id")?;
            apply_scope_mutation(
                self,
                &ctx,
                &args.realm,
                &client_id,
                ScopeKind::Optional,
                scope_id,
                ScopeMutationAction::Remove,
                dry_run,
            )
            .await?;
        }

        for scope_id in plan.added.iter() {
            validate_no_path_traversal(scope_id, "scope_id")?;
            apply_scope_mutation(
                self,
                &ctx,
                &args.realm,
                &client_id,
                ScopeKind::Optional,
                scope_id,
                ScopeMutationAction::Add,
                dry_run,
            )
            .await?;
        }

        Ok(CallToolResult::structured(json!(scope_mutation_summary(
            mutation_outcome(
                &plan.added,
                &plan.removed,
                dry_run,
                MutationOutcome::AlreadyMatch,
            ),
            &client_id,
            "exact_match",
            scope_kind_label(ScopeKind::Optional),
            plan.requested,
            plan.already_bound,
            plan.added,
            plan.removed,
            dry_run,
        ))))
    }
}
