//! # Users Tools
//!
//! MCP tools for managing Keycloak users, groups, and role mappings.
//!
//! ## Rationale
//! Provides a high-level interface for agents to perform user lifecycle tasks (create, delete,
//! password resets) and manage group/role assignments safely.
//!
//! ## Security Boundaries
//! * **Destructive Actions**: Deletion and password resets are gated by `keycloak-admin:users:write`.
//! * **Input Validation**: Strictly validates `user_id` as a UUID and `realm` for safe characters.
//!
//! ## References
//! * **DESIGN**: `docs/design/admin-mcp-architecture.md`

use axum::http::request::Parts;
use axum::http::Method;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::tool;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::errors::{tool_error, tool_text_result};
use crate::server::KcAdminMcp;
use crate::tools::shared::{auth_from_parts, require_roles_for_scopes, require_scopes};
use crate::tools::validation::{validate_no_path_traversal, validate_realm_name, validate_uuid};

/// Arguments for `users.list`.
/// Required scopes: `keycloak-admin:users:read` (configurable); safety: read-only.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UsersListArgs {
    pub realm: String,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub max: Option<u32>,
}

/// Arguments shared by user lookup tools.
/// Required scopes: `keycloak-admin:users:read` for read tools and `keycloak-admin:users:write` for `users.sessions.logout` (configurable); safety varies by tool.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UsersGetArgs {
    pub realm: String,
    pub user_id: String,
}

/// Arguments for `users.create`.
/// Required scopes: `keycloak-admin:users:write` (configurable); safety: writes user data.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UsersCreateArgs {
    pub realm: String,
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Arguments for `users.delete`.
/// Required scopes: `keycloak-admin:users:write` (configurable); safety: destructive.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UsersDeleteArgs {
    pub realm: String,
    pub user_id: String,
}

/// Arguments for `users.reset_password`.
/// Required scopes: `keycloak-admin:users:write` (configurable); safety: writes credentials.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UsersResetPasswordArgs {
    pub realm: String,
    pub user_id: String,
    pub new_password: String,
    #[serde(default)]
    pub temporary: Option<bool>,
}

/// Arguments for `users.required_actions.set`.
/// Required scopes: `keycloak-admin:users:write` (configurable); safety: writes account state.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UsersRequiredActionsArgs {
    pub realm: String,
    pub user_id: String,
    pub actions: Vec<String>,
}

/// Arguments for `users.groups.list`.
/// Required scopes: `keycloak-admin:users:read` (configurable); safety: read-only.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UsersGroupsListArgs {
    pub realm: String,
    pub user_id: String,
    #[serde(default)]
    pub brief_representation: Option<bool>,
}

/// Arguments for `users.groups.add` and `users.groups.remove`.
/// Required scopes: `keycloak-admin:users:write` (configurable); safety: writes group membership (removal currently lacks scope enforcement in handler).
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct UsersGroupModifyArgs {
    pub realm: String,
    pub user_id: String,
    pub group_id: String,
}

#[derive(Debug, Deserialize)]
struct UserRepresentation {
    id: Option<String>,
    username: Option<String>,
    email: Option<String>,
    enabled: Option<bool>,
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserConsentRepresentation {
    #[serde(rename = "clientId")]
    client_id: Option<String>,
    #[serde(rename = "createdDate")]
    created_date: Option<i64>,
    #[serde(rename = "lastUpdatedDate")]
    last_updated_date: Option<i64>,
    #[serde(rename = "grantedClientScopes")]
    granted_client_scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UserGroupRepresentation {
    id: Option<String>,
    name: Option<String>,
    path: Option<String>,
    #[serde(rename = "subGroupCount")]
    sub_group_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct UserSessionRepresentation {
    id: Option<String>,
    #[serde(rename = "userId")]
    user_id: Option<String>,
    username: Option<String>,
    #[serde(rename = "ipAddress")]
    ip_address: Option<String>,
    start: Option<i64>,
    #[serde(rename = "lastAccess")]
    last_access: Option<i64>,
    clients: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "transientUser")]
    transient_user: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RoleRepresentation {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    composite: Option<bool>,
    #[serde(rename = "clientRole")]
    client_role: Option<bool>,
    #[serde(rename = "containerId")]
    container_id: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct UserSummary {
    id: Option<String>,
    username: Option<String>,
    email: Option<String>,
    enabled: Option<bool>,
    first_name: Option<String>,
    last_name: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct UserConsentSummary {
    client_id: Option<String>,
    created_date: Option<i64>,
    last_updated_date: Option<i64>,
    granted_client_scopes: Option<Vec<String>>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct UserGroupSummary {
    id: Option<String>,
    name: Option<String>,
    path: Option<String>,
    sub_group_count: Option<u32>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct UserSessionSummary {
    id: Option<String>,
    user_id: Option<String>,
    username: Option<String>,
    ip_address: Option<String>,
    start: Option<i64>,
    last_access: Option<i64>,
    clients: Option<std::collections::HashMap<String, String>>,
    transient_user: Option<bool>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct RoleSummary {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    composite: Option<bool>,
    client_role: Option<bool>,
    container_id: Option<String>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct ClientRoleMappingSummary {
    client_id: Option<String>,
    client_name: Option<String>,
    roles: Vec<RoleSummary>,
}

impl From<UserRepresentation> for UserSummary {
    fn from(value: UserRepresentation) -> Self {
        Self {
            id: value.id,
            username: value.username,
            email: value.email,
            enabled: value.enabled,
            first_name: value.first_name,
            last_name: value.last_name,
        }
    }
}

impl From<UserConsentRepresentation> for UserConsentSummary {
    fn from(value: UserConsentRepresentation) -> Self {
        Self {
            client_id: value.client_id,
            created_date: value.created_date,
            last_updated_date: value.last_updated_date,
            granted_client_scopes: value.granted_client_scopes,
        }
    }
}

impl From<UserGroupRepresentation> for UserGroupSummary {
    fn from(value: UserGroupRepresentation) -> Self {
        Self {
            id: value.id,
            name: value.name,
            path: value.path,
            sub_group_count: value.sub_group_count,
        }
    }
}

impl From<UserSessionRepresentation> for UserSessionSummary {
    fn from(value: UserSessionRepresentation) -> Self {
        Self {
            id: value.id,
            user_id: value.user_id,
            username: value.username,
            ip_address: value.ip_address,
            start: value.start,
            last_access: value.last_access,
            clients: value.clients,
            transient_user: value.transient_user,
        }
    }
}

impl From<RoleRepresentation> for RoleSummary {
    fn from(value: RoleRepresentation) -> Self {
        Self {
            id: value.id,
            name: value.name,
            description: value.description,
            composite: value.composite,
            client_role: value.client_role,
            container_id: value.container_id,
        }
    }
}

mod access;
mod core;
mod groups;
mod password;

impl KcAdminMcp {
    pub fn tool_router_users() -> ToolRouter<KcAdminMcp> {
        Self::tool_router_users_core()
            + Self::tool_router_users_password()
            + Self::tool_router_users_groups()
            + Self::tool_router_users_access()
    }
}
fn role_summary_from_value(value: serde_json::Value) -> RoleSummary {
    serde_json::from_value::<RoleRepresentation>(value)
        .map(RoleSummary::from)
        .unwrap_or(RoleSummary {
            id: None,
            name: None,
            description: None,
            composite: None,
            client_role: None,
            container_id: None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Json;
    use axum::routing::{delete, get, post, put};
    use serde_json::json;

    use crate::test_support::{
        auth_context, build_config, build_server, parts_with_auth, TestServer,
    };

    async fn delete_handler() -> Json<serde_json::Value> {
        Json(json!({ "ok": true }))
    }

    async fn reset_password_handler(
        Json(payload): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        assert_eq!(payload.get("type"), Some(&json!("password")));
        Json(json!({}))
    }

    async fn groups_handler() -> Json<serde_json::Value> {
        Json(json!([
            {"id": "g1", "name": "group-1", "path": "/group-1", "subGroupCount": 0}
        ]))
    }

    async fn role_mappings_handler() -> Json<serde_json::Value> {
        Json(json!({
            "clientMappings": {
                "client-1": {
                    "client": "client-1-name",
                    "mappings": [
                        {
                            "id": "role-1",
                            "name": "role-a",
                            "description": "desc",
                            "composite": false,
                            "clientRole": false,
                            "containerId": "realm"
                        }
                    ]
                }
            }
        }))
    }

    async fn sessions_handler() -> Json<serde_json::Value> {
        Json(json!([
            {
                "id": "sess-1",
                "userId": "user-1",
                "username": "user-1",
                "ipAddress": "127.0.0.1",
                "start": 1,
                "lastAccess": 2,
                "clients": {"client": "app"},
                "transientUser": false
            }
        ]))
    }

    #[tokio::test]
    async fn users_delete_returns_structured_output() {
        let router = axum::Router::new().route(
            "/admin/realms/test/users/550e8400-e29b-41d4-a716-446655440000",
            delete(delete_handler),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.users.write.clone());
        let parts = parts_with_auth(ctx);
        let args = UsersDeleteArgs {
            realm: "test".to_string(),
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        };

        let result = mcp
            .users_delete(Parameters(args), Extension(parts))
            .await
            .expect("users delete result");

        let structured = result.structured_content.expect("structured content");
        assert_eq!(structured, json!({ "deleted": true }));

        server.shutdown();
    }

    #[tokio::test]
    async fn users_reset_password_returns_structured_output() {
        let router = axum::Router::new().route(
            "/admin/realms/test/users/550e8400-e29b-41d4-a716-446655440000/reset-password",
            put(reset_password_handler),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.users.write.clone());
        let parts = parts_with_auth(ctx);
        let args = UsersResetPasswordArgs {
            realm: "test".to_string(),
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            new_password: "password-1".to_string(),
            temporary: Some(true),
        };

        let result = mcp
            .users_reset_password(Parameters(args), Extension(parts))
            .await
            .expect("users reset password result");

        let structured = result.structured_content.expect("structured content");
        assert_eq!(structured, json!({ "reset": true }));

        server.shutdown();
    }

    #[tokio::test]
    async fn users_groups_list_returns_structured_output() {
        let router = axum::Router::new().route(
            "/admin/realms/test/users/550e8400-e29b-41d4-a716-446655440000/groups",
            get(groups_handler),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.users.read.clone());
        let parts = parts_with_auth(ctx);
        let args = UsersGroupsListArgs {
            realm: "test".to_string(),
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            brief_representation: None,
        };

        let result = mcp
            .users_groups_list(Parameters(args), Extension(parts))
            .await
            .expect("users groups list result");

        let structured = result.structured_content.expect("structured content");
        assert_eq!(
            structured,
            json!({
                "groups": [
                    {
                        "id": "g1",
                        "name": "group-1",
                        "path": "/group-1",
                        "sub_group_count": 0
                    }
                ]
            })
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn users_role_mappings_clients_returns_structured_output() {
        let router = axum::Router::new().route(
            "/admin/realms/test/users/550e8400-e29b-41d4-a716-446655440000/role-mappings",
            get(role_mappings_handler),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.users.read.clone());
        let parts = parts_with_auth(ctx);
        let args = UsersGetArgs {
            realm: "test".to_string(),
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        };

        let result = mcp
            .users_role_mappings_clients(Parameters(args), Extension(parts))
            .await
            .expect("users role mappings clients result");

        let structured = result.structured_content.expect("structured content");
        assert_eq!(
            structured,
            json!({
                "clients": [
                    {
                        "client_id": "client-1",
                        "client_name": "client-1-name",
                        "roles": [
                            {
                                "id": "role-1",
                                "name": "role-a",
                                "description": "desc",
                                "composite": false,
                                "client_role": false,
                                "container_id": "realm"
                            }
                        ]
                    }
                ]
            })
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn users_sessions_list_returns_structured_output() {
        let router = axum::Router::new().route(
            "/admin/realms/test/users/550e8400-e29b-41d4-a716-446655440000/sessions",
            get(sessions_handler),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.users.read.clone());
        let parts = parts_with_auth(ctx);
        let args = UsersGetArgs {
            realm: "test".to_string(),
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        };

        let result = mcp
            .users_sessions_list(Parameters(args), Extension(parts))
            .await
            .expect("users sessions list result");

        let structured = result.structured_content.expect("structured content");
        assert_eq!(
            structured,
            json!({
                "sessions": [
                    {
                        "id": "sess-1",
                        "user_id": "user-1",
                        "username": "user-1",
                        "ip_address": "127.0.0.1",
                        "start": 1,
                        "last_access": 2,
                        "clients": {"client": "app"},
                        "transient_user": false
                    }
                ]
            })
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn users_required_actions_set_returns_structured_output() {
        let router = axum::Router::new().route(
            "/admin/realms/test/users/550e8400-e29b-41d4-a716-446655440000",
            put(|Json(_payload): Json<serde_json::Value>| async move { Json(json!({})) }),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.users.write.clone());
        let parts = parts_with_auth(ctx);
        let args = UsersRequiredActionsArgs {
            realm: "test".to_string(),
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            actions: vec!["VERIFY_EMAIL".to_string()],
        };

        let result = mcp
            .users_required_actions_set(Parameters(args), Extension(parts))
            .await
            .expect("users required actions set result");

        let structured = result.structured_content.expect("structured content");
        assert_eq!(structured, json!({ "ok": true }));

        server.shutdown();
    }

    #[tokio::test]
    async fn users_sessions_logout_returns_structured_output() {
        let router = axum::Router::new().route(
            "/admin/realms/test/users/550e8400-e29b-41d4-a716-446655440000/logout",
            post(|| async move { Json(json!({})) }),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.users.write.clone());
        let parts = parts_with_auth(ctx);
        let args = UsersGetArgs {
            realm: "test".to_string(),
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        };

        let result = mcp
            .users_sessions_logout(Parameters(args), Extension(parts))
            .await
            .expect("users sessions logout result");

        let structured = result.structured_content.expect("structured content");
        assert_eq!(structured, json!({ "ok": true }));

        server.shutdown();
    }

    #[tokio::test]
    async fn users_groups_add_and_remove_returns_structured_output() {
        let router = axum::Router::new()
            .route(
                "/admin/realms/test/users/550e8400-e29b-41d4-a716-446655440000/groups/550e8400-e29b-41d4-a716-446655440001",
                put(|| async move { Json(json!({})) }),
            )
            .route(
                "/admin/realms/test/users/550e8400-e29b-41d4-a716-446655440000/groups/550e8400-e29b-41d4-a716-446655440001",
                delete(|| async move { Json(json!({})) }),
            );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.users.write.clone());
        let parts = parts_with_auth(ctx.clone());
        let args = UsersGroupModifyArgs {
            realm: "test".to_string(),
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            group_id: "550e8400-e29b-41d4-a716-446655440001".to_string(),
        };

        let result = mcp
            .users_groups_add(Parameters(args.clone()), Extension(parts))
            .await
            .expect("users groups add result");
        let structured = result.structured_content.expect("structured content");
        assert_eq!(structured, json!({ "ok": true }));

        let parts = parts_with_auth(ctx);
        let result = mcp
            .users_groups_remove(Parameters(args), Extension(parts))
            .await
            .expect("users groups remove result");
        let structured = result.structured_content.expect("structured content");
        assert_eq!(structured, json!({ "ok": true }));

        server.shutdown();
    }

    #[tokio::test]
    async fn users_consent_list_returns_structured_output() {
        let router = axum::Router::new().route(
            "/admin/realms/test/users/550e8400-e29b-41d4-a716-446655440000/consents",
            get(|| async move {
                Json(json!([
                    {
                        "clientId": "client-1",
                        "createdDate": 1,
                        "lastUpdatedDate": 2,
                        "grantedClientScopes": ["scope-a"]
                    }
                ]))
            }),
        );
        let server = TestServer::spawn(router).await;

        let config = build_config(server.base_url.clone(), "http://127.0.0.1:9999".to_string());
        let mcp = build_server(config);

        let ctx = auth_context(mcp.config.scope_map.users.read.clone());
        let parts = parts_with_auth(ctx);
        let args = UsersGetArgs {
            realm: "test".to_string(),
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        };

        let result = mcp
            .users_consent_list(Parameters(args), Extension(parts))
            .await
            .expect("users consent list result");

        let structured = result.structured_content.expect("structured content");
        assert_eq!(
            structured,
            json!({
                "consents": [
                    {
                        "client_id": "client-1",
                        "created_date": 1,
                        "last_updated_date": 2,
                        "granted_client_scopes": ["scope-a"]
                    }
                ]
            })
        );

        server.shutdown();
    }
}
