//! # Tool Bundles
//!
//! Categorizes MCP tools into logical bundles for dynamic injection and least-privilege enforcement.
//!
//! ## Rationale
//! To support the "Triple-Lock" security model, agents should only be granted tools relevant
//! to their current task. This module defines the canonical grouping of Keycloak admin tools.
//!
//! ## Security Boundaries
//! * **Informational Only**: This registry describes the tools; it does not bypass scope enforcement.
//! * **Transparency**: Allows orchestrators to verify that an agent has a minimized tool surface.

use schemars::JsonSchema;
use serde::Serialize;

/// Defines ToolBundle.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ToolBundle {
    pub name: &'static str,
    pub description: &'static str,
    pub tools: &'static [&'static str],
}

pub const TOOL_BUNDLES: &[ToolBundle] = &[
    ToolBundle {
        name: "users",
        description: "User lifecycle management, sessions, and group/role memberships.",
        tools: &[
            "users.list",
            "users.get",
            "users.create",
            "users.delete",
            "users.reset_password",
            "users.required_actions.set",
            "users.groups.list",
            "users.groups.add",
            "users.groups.remove",
            "users.role_mappings.realm",
            "users.role_mappings.clients",
            "users.consent.list",
            "users.sessions.list",
            "users.sessions.logout",
        ],
    },
    ToolBundle {
        name: "groups",
        description: "Realm-level group hierarchy and member management.",
        tools: &[
            "groups.list",
            "groups.get",
            "groups.create",
            "groups.delete",
            "groups.members.list",
            "groups.role_mappings.realm",
            "groups.role_mappings.clients",
        ],
    },
    ToolBundle {
        name: "clients",
        description: "OIDC/SAML client registration, configuration, and secret management.",
        tools: &[
            "clients.list",
            "clients.get",
            "clients.create",
            "clients.update",
            "clients.delete",
            "clients.secret.get",
            "clients.secret.regenerate",
            "clients.service_account_user.get",
        ],
    },
    ToolBundle {
        name: "client_scopes",
        description: "Management of shared client scopes and protocol mappers.",
        tools: &[
            "client_scopes.list",
            "client_scopes.get",
            "client_scopes.create",
            "client_scopes.delete",
        ],
    },
    ToolBundle {
        name: "roles",
        description: "Realm and client-level role definitions.",
        tools: &[
            "roles.realm.list",
            "roles.realm.get",
            "roles.realm.create",
            "roles.realm.delete",
            "roles.client.list",
            "roles.client.get",
            "roles.client.create",
            "roles.client.delete",
        ],
    },
    ToolBundle {
        name: "realms",
        description: "Realm configuration and management.",
        tools: &[
            "realms.list",
            "realms.get",
            "realms.create",
            "realms.delete",
        ],
    },
    ToolBundle {
        name: "identity_providers",
        description: "External OIDC/SAML identity provider configuration.",
        tools: &[
            "identity_providers.list",
            "identity_providers.get",
            "identity_providers.create",
            "identity_providers.delete",
        ],
    },
    ToolBundle {
        name: "events",
        description: "Audit and user event logging configuration.",
        tools: &[
            "events.config.get",
            "events.config.update",
            "events.admin.list",
            "events.user.list",
        ],
    },
    ToolBundle {
        name: "observability",
        description: "Server health and uptime metrics.",
        tools: &["observability.health", "observability.uptime"],
    },
];
