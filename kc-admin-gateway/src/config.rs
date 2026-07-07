//! # Gateway Configuration
//!
//! Handles configuration loading and credential fallback for the security gateway.
//!
//! ## Rationale
//! Centralizes all gateway settings, ensuring that mTLS requirements, audit hashing,
//! and Keycloak connection details are loaded from a trusted source.
//!
//! ## Security Boundaries
//! * **Secret Extraction**: Decouples environment variables from credentials stored in `CREDENTIALS_DIRECTORY`.
//! * **mTLS Gating**: Controls whether the gateway requires client certificates.

use std::time::{Duration, Instant};
use std::{fs, path::PathBuf};

/// Client authentication options for introspection/exchange clients.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug)]
pub enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
}

/// Gateway runtime configuration loaded from environment/credentials files.
///
/// # Errors
/// * This type does not emit errors directly.
///
/// # Security
/// * Treat all inputs as untrusted; avoid logging secrets or raw tokens.
///
/// # Caveats
/// * None.
#[derive(Clone, Debug)]
pub struct GatewayConfig {
    pub host: String,
    pub port: u16,
    pub log_level: String,
    pub request_timeout: Duration,
    pub tls_cert_pem: Option<String>,
    pub tls_key_pem: Option<String>,
    pub tls_client_ca_pem: Option<String>,
    pub mtls_required: bool,
    pub audit_hash_identifiers: bool,
    pub audit_hash_salt: Option<String>,
    pub log_exchange_body: bool,
    pub log_exchange_body_max_bytes: usize,
    pub admin_base_url: String,
    pub admin_host_header: Option<String>,
    pub admin_forwarded_proto: Option<String>,
    pub introspection_url: String,
    pub introspection_client_id: String,
    pub introspection_client_secret: String,
    pub introspection_auth_method: ClientAuthMethod,
    pub expected_issuer: Option<String>,
    pub expected_audience: Option<String>,
    pub allowed_azp: Vec<String>,
    pub build_production: bool,
    pub allow_open_azp: bool,
    pub allow_open_azp_reason: Option<String>,
    pub allow_open_azp_ttl_s: Option<String>,
    pub allow_open_azp_expires_at: Option<Instant>,
    pub exchange_enabled: bool,
    pub exchange_url: String,
    pub exchange_client_id: String,
    pub exchange_client_secret: String,
    pub exchange_auth_method: ClientAuthMethod,
    pub exchange_audience: Option<String>,
    pub exchange_resource: Option<String>,
}

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_optional(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn env_u16(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .and_then(|value| {
            let value = value.to_ascii_lowercase();
            match value.as_str() {
                "1" | "true" | "yes" | "on" => Some(true),
                "0" | "false" | "no" | "off" => Some(false),
                _ => None,
            }
        })
        .unwrap_or(default)
}

fn env_list(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn credential_path(name: &str) -> Option<PathBuf> {
    let dir = std::env::var("CREDENTIALS_DIRECTORY").ok()?;
    Some(PathBuf::from(dir).join(name))
}

fn read_credential(name: &str) -> Option<String> {
    let path = credential_path(name)?;
    let contents = fs::read_to_string(path).ok()?;
    Some(contents.trim_end().to_string())
}

fn env_secret(env_name: &str, credential_name: &str) -> String {
    let value = env(env_name, "");
    if !value.trim().is_empty() {
        return value;
    }
    read_credential(credential_name).unwrap_or_default()
}

fn env_secret_optional(env_name: &str, credential_name: &str) -> Option<String> {
    let value = env_optional(env_name);
    if value.is_some() {
        return value;
    }
    read_credential(credential_name)
}

/// Load the gateway configuration from env vars with credential fallback.
///
/// # Security
/// * **Credentials**: Prefers the systemd-style `CREDENTIALS_DIRECTORY` for sensitive PEM files and secrets.
///
/// # Errors
/// * Does not return errors.
///
/// # Caveats
/// * None.
pub fn load_config() -> GatewayConfig {
    let log_level = env("KC_GATEWAY_LOG_LEVEL", "info");
    let introspection_auth = env(
        "KC_GATEWAY_INTROSPECTION_AUTH_METHOD",
        "client_secret_basic",
    );
    let exchange_auth = env("KC_GATEWAY_EXCHANGE_AUTH_METHOD", "client_secret_basic");
    let introspection_auth_method = match introspection_auth.as_str() {
        "client_secret_post" => ClientAuthMethod::ClientSecretPost,
        _ => ClientAuthMethod::ClientSecretBasic,
    };
    let exchange_auth_method = match exchange_auth.as_str() {
        "client_secret_post" => ClientAuthMethod::ClientSecretPost,
        _ => ClientAuthMethod::ClientSecretBasic,
    };

    GatewayConfig {
        host: env("KC_GATEWAY_HOST", "127.0.0.1"),
        port: env_u16("KC_GATEWAY_PORT", 9300),
        log_level,
        request_timeout: Duration::from_millis(env_u64("KC_GATEWAY_REQUEST_TIMEOUT_MS", 5000)),
        tls_cert_pem: env_secret_optional("KC_GATEWAY_TLS_CERT", "kc_gateway_tls_cert"),
        tls_key_pem: env_secret_optional("KC_GATEWAY_TLS_KEY", "kc_gateway_tls_key"),
        tls_client_ca_pem: env_secret_optional(
            "KC_GATEWAY_TLS_CLIENT_CA",
            "kc_gateway_tls_client_ca",
        ),
        mtls_required: env_bool("KC_GATEWAY_MTLS_REQUIRED", false),
        audit_hash_identifiers: env_bool("KC_GATEWAY_AUDIT_HASH_IDENTIFIERS", false),
        audit_hash_salt: env_secret_optional(
            "KC_GATEWAY_AUDIT_HASH_SALT",
            "kc_gateway_audit_hash_salt",
        ),
        log_exchange_body: env_bool("KC_GATEWAY_LOG_EXCHANGE_BODY", false),
        log_exchange_body_max_bytes: env_usize("KC_GATEWAY_LOG_EXCHANGE_BODY_MAX_BYTES", 2048),
        admin_base_url: env("KC_GATEWAY_ADMIN_BASE_URL", ""),
        admin_host_header: env_optional("KC_GATEWAY_ADMIN_HOST_HEADER"),
        admin_forwarded_proto: env_optional("KC_GATEWAY_ADMIN_FORWARDED_PROTO"),
        introspection_url: env("KC_GATEWAY_INTROSPECTION_URL", ""),
        introspection_client_id: env("KC_GATEWAY_INTROSPECTION_CLIENT_ID", ""),
        introspection_client_secret: env_secret(
            "KC_GATEWAY_INTROSPECTION_CLIENT_SECRET",
            "kc_gateway_introspection_client_secret",
        ),
        introspection_auth_method,
        expected_issuer: env_optional("KC_GATEWAY_EXPECTED_ISSUER"),
        expected_audience: env_optional("KC_GATEWAY_EXPECTED_AUDIENCE"),
        allowed_azp: env_list("KC_GATEWAY_ALLOWED_AZP"),
        build_production: env_bool(
            "KC_GATEWAY_BUILD_PRODUCTION",
            env_bool("MCP_BUILD_PRODUCTION", false),
        ),
        allow_open_azp: env_bool("KC_GATEWAY_ALLOW_OPEN_AZP", false),
        allow_open_azp_reason: env_optional("KC_GATEWAY_ALLOW_OPEN_AZP_REASON"),
        allow_open_azp_ttl_s: env_optional("KC_GATEWAY_ALLOW_OPEN_AZP_TTL_S"),
        allow_open_azp_expires_at: None,
        exchange_enabled: env_bool("KC_GATEWAY_EXCHANGE_ENABLED", true),
        exchange_url: env("KC_GATEWAY_EXCHANGE_URL", ""),
        exchange_client_id: env("KC_GATEWAY_EXCHANGE_CLIENT_ID", ""),
        exchange_client_secret: env_secret(
            "KC_GATEWAY_EXCHANGE_CLIENT_SECRET",
            "kc_gateway_exchange_client_secret",
        ),
        exchange_auth_method,
        exchange_audience: env_optional("KC_GATEWAY_EXCHANGE_AUDIENCE"),
        exchange_resource: env_optional("KC_GATEWAY_EXCHANGE_RESOURCE"),
    }
}
