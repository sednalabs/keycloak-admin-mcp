//! # Keycloak Admin Gateway
//!
//! The dedicated security gateway for Keycloak admin operations.
//!
//! ## Rationale
//! Centralizes all privileged access to the Keycloak Admin API. The MCP server delegates to this
//! gateway, which performs token exchange (RFC 8693) to downscope high-privilege machine tokens
//! into specific operational scopes (e.g., `users:read`).
//!
//! ## Security Boundaries
//! * **Authentication**: Validates incoming mTLS connections and introspection tokens.
//! * **Policy Enforcement**: Maps URL paths to required scopes (e.g. `/users` -> `keycloak-admin:users:read`).
//! * **Isolation**: Only this process holds the `client_secret` capable of administrative actions.
//!
//! ## References
//! * **DESIGN**: `docs/design/admin-mcp-gateway-protocol.md`
//! * **SPEC**: [OAuth 2.0 Token Exchange (RFC 8693)](https://tools.ietf.org/html/rfc8693)

mod auth;
mod config;
mod edge;
mod errors;
mod exchange;
mod handlers;
mod http;
mod log_sanitize;
mod logging;
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::routing::{any, get};
use axum::Router;
use mcp_toolkit_auth::{AuthConfig, AuthMode, Authenticator, ClientAuthMethod as McpAuthMethod};

use crate::config::{ClientAuthMethod, GatewayConfig};
use crate::errors::GatewayError;
use crate::handlers::{health, proxy_admin, AppState};
use crate::logging::init_tracing;
use crate::tls::build_tls_config;

#[tokio::main]
async fn main() {
    let config = config::load_config();
    init_tracing(&config.log_level);

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "gateway panic");
        default_hook(info);
    }));

    if let Err(err) = rustls::crypto::aws_lc_rs::default_provider().install_default() {
        tracing::error!(error = ?err, "failed to install rustls crypto provider");
        std::process::exit(1);
    }

    let config = match validate_config(config) {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(error = %err, "invalid gateway configuration");
            std::process::exit(1);
        }
    };

    let auth_config = build_auth_config(&config);
    let authenticator = match Authenticator::new(auth_config) {
        Ok(auth) => auth,
        Err(err) => {
            tracing::error!(error = ?err, "failed to initialize authenticator");
            std::process::exit(1);
        }
    };

    let state = match AppState::new(config.clone(), authenticator) {
        Ok(state) => Arc::new(state),
        Err(err) => {
            tracing::error!(error = %err, "failed to initialize gateway");
            std::process::exit(1);
        }
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/admin", any(proxy_admin))
        .route("/admin/{*path}", any(proxy_admin))
        .layer(axum::middleware::from_fn(edge::edge_guard))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("invalid host/port");

    let tls_config = match build_tls_config(&config) {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(error = %err, "invalid TLS configuration");
            std::process::exit(1);
        }
    };

    tracing::info!(%addr, tls = tls_config.is_some(), "kc-admin-gateway listening");

    if let Some(tls_config) = tls_config {
        if let Err(err) = axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await
        {
            tracing::error!(error = %err, "gateway TLS server exited");
        }
        return;
    }

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, "failed to bind gateway socket");
            std::process::exit(1);
        }
    };

    if let Err(err) = axum::serve(listener, app).await {
        tracing::error!(error = %err, "gateway server exited");
    }
}

fn validate_config(mut cfg: GatewayConfig) -> Result<GatewayConfig, GatewayError> {
    ensure_value("KC_GATEWAY_ADMIN_BASE_URL", &cfg.admin_base_url)?;
    ensure_value("KC_GATEWAY_INTROSPECTION_URL", &cfg.introspection_url)?;
    ensure_value(
        "KC_GATEWAY_INTROSPECTION_CLIENT_ID",
        &cfg.introspection_client_id,
    )?;
    ensure_secret(
        "KC_GATEWAY_INTROSPECTION_CLIENT_SECRET",
        &cfg.introspection_client_secret,
        &cfg.introspection_auth_method,
    )?;
    ensure_identity_expectations(&cfg)?;
    cfg.allow_open_azp_expires_at = ensure_azp_allowlist(&cfg)?;

    if cfg.exchange_enabled {
        ensure_value("KC_GATEWAY_EXCHANGE_URL", &cfg.exchange_url)?;
        ensure_value("KC_GATEWAY_EXCHANGE_CLIENT_ID", &cfg.exchange_client_id)?;
        ensure_secret(
            "KC_GATEWAY_EXCHANGE_CLIENT_SECRET",
            &cfg.exchange_client_secret,
            &cfg.exchange_auth_method,
        )?;
    }

    Ok(cfg)
}

fn ensure_value(name: &str, value: &str) -> Result<(), GatewayError> {
    if value.trim().is_empty() {
        Err(GatewayError::InvalidConfig(format!("{name} is required")))
    } else {
        Ok(())
    }
}

fn ensure_secret(name: &str, value: &str, method: &ClientAuthMethod) -> Result<(), GatewayError> {
    match method {
        ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
            ensure_value(name, value)
        }
    }
}

fn ensure_azp_allowlist(cfg: &GatewayConfig) -> Result<Option<Instant>, GatewayError> {
    if cfg.allow_open_azp {
        if cfg
            .allow_open_azp_reason
            .as_deref()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(GatewayError::InvalidConfig(
                "KC_GATEWAY_ALLOW_OPEN_AZP=1 requires KC_GATEWAY_ALLOW_OPEN_AZP_REASON".to_string(),
            ));
        }
        let ttl_s = cfg
            .allow_open_azp_ttl_s
            .as_deref()
            .ok_or_else(|| {
                GatewayError::InvalidConfig(
                    "KC_GATEWAY_ALLOW_OPEN_AZP=1 requires KC_GATEWAY_ALLOW_OPEN_AZP_TTL_S>0"
                        .to_string(),
                )
            })
            .and_then(|raw| {
                raw.parse::<u64>().map_err(|_| {
                    GatewayError::InvalidConfig(
                        "KC_GATEWAY_ALLOW_OPEN_AZP_TTL_S must be a positive integer".to_string(),
                    )
                })
            })?;
        if ttl_s == 0 {
            return Err(GatewayError::InvalidConfig(
                "KC_GATEWAY_ALLOW_OPEN_AZP=1 requires KC_GATEWAY_ALLOW_OPEN_AZP_TTL_S>0"
                    .to_string(),
            ));
        }
        return break_glass_deadline(ttl_s).map(Some);
    }

    if cfg.build_production && cfg.allowed_azp.is_empty() && !cfg.allow_open_azp {
        return Err(GatewayError::InvalidConfig(
            "KC_GATEWAY_ALLOWED_AZP is required when KC_GATEWAY_BUILD_PRODUCTION=1 (set KC_GATEWAY_ALLOW_OPEN_AZP=1 for break-glass)"
                .to_string(),
        ));
    }
    Ok(None)
}

fn break_glass_deadline(ttl_s: u64) -> Result<Instant, GatewayError> {
    Instant::now()
        .checked_add(Duration::from_secs(ttl_s))
        .ok_or_else(|| {
            GatewayError::InvalidConfig("break-glass TTL is too large to represent".to_string())
        })
}

fn ensure_identity_expectations(cfg: &GatewayConfig) -> Result<(), GatewayError> {
    if !cfg.build_production {
        return Ok(());
    }
    if cfg
        .expected_issuer
        .as_deref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        return Err(GatewayError::InvalidConfig(
            "KC_GATEWAY_EXPECTED_ISSUER is required when KC_GATEWAY_BUILD_PRODUCTION=1".to_string(),
        ));
    }
    if cfg
        .expected_audience
        .as_deref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        return Err(GatewayError::InvalidConfig(
            "KC_GATEWAY_EXPECTED_AUDIENCE is required when KC_GATEWAY_BUILD_PRODUCTION=1"
                .to_string(),
        ));
    }
    Ok(())
}

fn build_auth_config(cfg: &GatewayConfig) -> AuthConfig {
    let method = match cfg.introspection_auth_method {
        ClientAuthMethod::ClientSecretBasic => McpAuthMethod::ClientSecretBasic,
        ClientAuthMethod::ClientSecretPost => McpAuthMethod::ClientSecretPost,
    };

    AuthConfig {
        mode: AuthMode::Introspection,
        introspection_url: Some(cfg.introspection_url.clone()),
        introspection_client_id: Some(cfg.introspection_client_id.clone()),
        introspection_client_secret: Some(cfg.introspection_client_secret.clone()),
        introspection_auth_method: method,
        introspection_cache_ttl_s: 0.0,
        strict_oauth: true,
        jwks_url: None,
        issuer: cfg.expected_issuer.clone(),
        audience: cfg.expected_audience.clone(),
        required_scopes: vec![],
        jti_ttl_s: 0.0,
        jti_cache_size: 0,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::validate_config;
    use crate::config::{ClientAuthMethod, GatewayConfig};

    fn base_gateway_config() -> GatewayConfig {
        GatewayConfig {
            host: "127.0.0.1".to_string(),
            port: 9300,
            log_level: "info".to_string(),
            request_timeout: Duration::from_secs(5),
            tls_cert_pem: None,
            tls_key_pem: None,
            tls_client_ca_pem: None,
            mtls_required: false,
            audit_hash_identifiers: false,
            audit_hash_salt: None,
            log_exchange_body: false,
            log_exchange_body_max_bytes: 2048,
            admin_base_url: "https://keycloak.example".to_string(),
            admin_host_header: None,
            admin_forwarded_proto: None,
            introspection_url: "https://keycloak.example/realms/example-realm/protocol/openid-connect/token/introspect".to_string(),
            introspection_client_id: "gateway-introspect".to_string(),
            introspection_client_secret: "secret".to_string(),
            introspection_auth_method: ClientAuthMethod::ClientSecretBasic,
            expected_issuer: Some("https://keycloak.example/realms/example-realm".to_string()),
            expected_audience: Some("kc-admin-gateway".to_string()),
            allowed_azp: vec!["kc-admin-mcp".to_string()],
            build_production: true,
            allow_open_azp: false,
            allow_open_azp_reason: None,
            allow_open_azp_ttl_s: None,
            allow_open_azp_expires_at: None,
            exchange_enabled: true,
            exchange_url: "https://keycloak.example/realms/example-realm/protocol/openid-connect/token".to_string(),
            exchange_client_id: "gateway-exchange".to_string(),
            exchange_client_secret: "secret".to_string(),
            exchange_auth_method: ClientAuthMethod::ClientSecretBasic,
            exchange_audience: None,
            exchange_resource: None,
        }
    }

    #[test]
    fn validate_config_rejects_open_azp_allowlist_in_production() {
        let mut cfg = base_gateway_config();
        cfg.allowed_azp = Vec::new();
        let err = validate_config(cfg).expect_err("production config should require azp allowlist");
        assert!(err
            .to_string()
            .contains("KC_GATEWAY_ALLOWED_AZP is required"));
    }

    #[test]
    fn validate_config_allows_break_glass_open_azp_in_production() {
        let mut cfg = base_gateway_config();
        cfg.allowed_azp = Vec::new();
        cfg.allow_open_azp = true;
        cfg.allow_open_azp_reason = Some("temporary emergency rollout".to_string());
        cfg.allow_open_azp_ttl_s = Some("3600".to_string());
        let cfg = validate_config(cfg).expect("break-glass open allowlist should be accepted");
        assert!(cfg
            .allow_open_azp_expires_at
            .is_some_and(|deadline| deadline > Instant::now()));
    }

    #[test]
    fn validate_config_rejects_missing_expected_issuer_in_production() {
        let mut cfg = base_gateway_config();
        cfg.expected_issuer = None;
        let err =
            validate_config(cfg).expect_err("production config should require expected issuer");
        assert!(err
            .to_string()
            .contains("KC_GATEWAY_EXPECTED_ISSUER is required"));
    }

    #[test]
    fn validate_config_rejects_missing_expected_audience_in_production() {
        let mut cfg = base_gateway_config();
        cfg.expected_audience = None;
        let err =
            validate_config(cfg).expect_err("production config should require expected audience");
        assert!(err
            .to_string()
            .contains("KC_GATEWAY_EXPECTED_AUDIENCE is required"));
    }

    #[test]
    fn validate_config_rejects_break_glass_without_reason() {
        let mut cfg = base_gateway_config();
        cfg.allowed_azp = Vec::new();
        cfg.allow_open_azp = true;
        cfg.allow_open_azp_ttl_s = Some("3600".to_string());
        let err = validate_config(cfg).expect_err("break-glass open azp should require reason");
        assert!(err.to_string().contains("KC_GATEWAY_ALLOW_OPEN_AZP_REASON"));
    }

    #[test]
    fn validate_config_rejects_break_glass_without_ttl() {
        let mut cfg = base_gateway_config();
        cfg.allowed_azp = Vec::new();
        cfg.allow_open_azp = true;
        cfg.allow_open_azp_reason = Some("temporary emergency rollout".to_string());
        let err = validate_config(cfg).expect_err("break-glass open azp should require ttl");
        assert!(err.to_string().contains("KC_GATEWAY_ALLOW_OPEN_AZP_TTL_S"));
    }

    #[test]
    fn validate_config_rejects_break_glass_with_invalid_ttl() {
        let mut cfg = base_gateway_config();
        cfg.allowed_azp = Vec::new();
        cfg.allow_open_azp = true;
        cfg.allow_open_azp_reason = Some("temporary emergency rollout".to_string());
        cfg.allow_open_azp_ttl_s = Some("invalid".to_string());
        let err = validate_config(cfg).expect_err("break-glass open azp should validate ttl");
        assert!(err
            .to_string()
            .contains("KC_GATEWAY_ALLOW_OPEN_AZP_TTL_S must be a positive integer"));
    }
}
