//! # Edge Hardening
//!
//! Middleware for enforcing network-level security invariants.
//!
//! ## Rationale
//! Protects the MCP server from common HTTP-level attacks and ensures that authentication
//! headers follow a strict format before being processed by the auth layer.
//!
//! ## Security Boundaries
//! * **Matrix Parameter Rejection**: Blocks paths containing `;` to prevent cache poisoning and ACL bypass.
//! * **Strict Bearer Parsing**: Rejects malformed `Authorization` headers (e.g. with extra whitespace or control chars).
//! * **Path Confusion Rejection**: Blocks dot-segment and encoded-separator path confusion vectors.

use axum::body::Body;
use axum::http::{header::AUTHORIZATION, HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

/// Edge hardening middleware.
///
/// # Security
/// * **Rejection**: Returns `400 Bad Request` if matrix parameters are present or if auth headers are malformed.
///
/// # Errors
/// * Returns an error if the operation fails.
///
/// # Caveats
/// * None.
pub async fn edge_guard(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let path = req.uri().path();
    if contains_matrix_params(path) || contains_path_confusion(path) {
        return Err(StatusCode::BAD_REQUEST);
    }

    ensure_strict_bearer(req.headers()).map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok(next.run(req).await)
}

fn ensure_strict_bearer(headers: &HeaderMap) -> Result<(), &'static str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err("multiple authorization headers");
    }

    let raw = value.to_str().map_err(|_| "invalid authorization header")?;

    if raw.trim() != raw {
        return Err("authorization header has leading/trailing whitespace");
    }

    if raw.chars().any(|ch| ch.is_control()) {
        return Err("authorization header contains control characters");
    }

    if raw.matches(' ').count() != 1 {
        return Err("authorization header must contain a single space separator");
    }

    let (scheme, token) = raw
        .split_once(' ')
        .ok_or("authorization header missing space")?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err("authorization scheme must be Bearer");
    }

    if token.is_empty() {
        return Err("empty bearer token");
    }

    Ok(())
}

fn contains_matrix_params(path: &str) -> bool {
    path.contains(';')
}

fn contains_path_confusion(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
        return true;
    }
    if path.contains('\\') {
        return true;
    }
    path.split('/').any(|segment| matches!(segment, "." | ".."))
}

#[cfg(test)]
mod tests {
    use super::{
        contains_matrix_params, contains_path_confusion, edge_guard, ensure_strict_bearer,
    };
    use axum::http::header::AUTHORIZATION;
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn ok_handler() -> impl IntoResponse {
        StatusCode::OK
    }

    fn app() -> Router {
        Router::new()
            .route("/", get(ok_handler))
            .layer(axum::middleware::from_fn(edge_guard))
    }

    #[test]
    fn allows_missing_authorization_header() {
        let headers = HeaderMap::new();
        assert!(ensure_strict_bearer(&headers).is_ok());
    }

    #[test]
    fn rejects_multiple_authorization_headers() {
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer one"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer two"));
        assert!(ensure_strict_bearer(&headers).is_err());
    }

    #[test]
    fn rejects_invalid_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer  token"));
        assert!(ensure_strict_bearer(&headers).is_err());
    }

    #[test]
    fn rejects_matrix_params() {
        assert!(contains_matrix_params("/admin/realms;foo/test"));
        assert!(contains_matrix_params("/admin/realms/test;v=1"));
        assert!(!contains_matrix_params("/admin/realms/test"));
    }

    #[test]
    fn rejects_path_confusion_vectors() {
        assert!(contains_path_confusion("/mcp/../admin"));
        assert!(contains_path_confusion("/mcp/%2e%2e/admin"));
        assert!(contains_path_confusion("/mcp/%2Fadmin"));
        assert!(contains_path_confusion("/mcp\\admin"));
        assert!(!contains_path_confusion("/mcp"));
    }

    #[tokio::test]
    async fn edge_guard_allows_missing_authorization_header() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn edge_guard_rejects_invalid_authorization_header() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(AUTHORIZATION, HeaderValue::from_static("Bearer  token"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn edge_guard_rejects_matrix_params_in_path() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/admin/realms;foo/test")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn edge_guard_rejects_path_confusion_in_path() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/mcp/%2e%2e/admin")
                    .body(axum::body::Body::empty())
                    .expect("request build"),
            )
            .await
            .expect("edge response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
