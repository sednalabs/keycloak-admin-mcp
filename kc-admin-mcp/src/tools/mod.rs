//! # Tool Modules
//!
//! Composition root for all Keycloak administrative tools.
//!
//! ## Rationale
//! Organizes tools into domain-specific modules (users, clients, groups, etc.) to keep the
//! server implementation maintainable. It ensures that common validation and auth helpers
//! are shared across all tools.
//!
//! ## Security Boundaries
//! * **Consolidated Validation**: All path parameters are validated for UUID format and path traversal.
//! * **Centralized Auth**: Every tool call must pass through `require_scopes` and `require_roles_for_scopes`.

pub mod bundles;
pub mod client_scopes;
pub mod clients;
pub mod events;
pub mod groups;
pub mod identity_providers;
pub mod observability;
pub mod realms;
pub mod roles;
pub mod shared;
pub mod users;
pub mod validation;
