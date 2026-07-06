//! # Gateway Edge Hardening
//!
//! Middleware for enforcing gateway-level security invariants.
//!
//! ## Rationale
//! Provides a first line of defense at the gateway boundary, ensuring that requests
//! are well-formed and meet basic security criteria before any expensive token
//! introspection or exchange occurs.
//!
//! ## Security Boundaries
//! * **Matrix Parameter Rejection**: Prevents path-based attacks (cache poisoning, ACL bypass).
//! * **Consolidated Auth Header**: Ensures exactly one `Authorization` header exists and is valid.
//! * **Path Confusion Rejection**: Blocks dot-segment and encoded-separator path confusion vectors.

use axum::body::Body;
use axum::http::{header::AUTHORIZATION, HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use mcp_toolkit_policy_core::{contains_matrix_params, contains_path_confusion};

use crate::auth::validate_bearer_header;

/// Edge guard middleware for the gateway.
///
/// # Security
/// * **Fail-Closed**: Blocks requests with multiple auth headers or unsafe path segments.
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
    validate_bearer_header(raw).map_err(|_| "invalid authorization header")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::http::{header::AUTHORIZATION, HeaderValue, Request, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    use super::{contains_matrix_params, contains_path_confusion, edge_guard};

    async fn ok_handler() -> impl IntoResponse {
        StatusCode::OK
    }

    fn app() -> Router {
        Router::new()
            .route("/", get(ok_handler))
            .layer(axum::middleware::from_fn(edge_guard))
    }

    #[tokio::test]
    async fn allows_missing_authorization_header() {
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
    async fn rejects_invalid_authorization_header() {
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
    async fn rejects_matrix_params_in_path() {
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

    #[test]
    fn matrix_param_detection() {
        assert!(contains_matrix_params("/admin/realms;foo/test"));
        assert!(contains_matrix_params("/admin/realms/test;v=1"));
        assert!(!contains_matrix_params("/admin/realms/test"));
    }

    #[test]
    fn path_confusion_detection() {
        assert!(contains_path_confusion("/admin/realms/../users"));
        assert!(contains_path_confusion("/admin/realms/%2e%2e/users"));
        assert!(contains_path_confusion("/admin/realms/%2Fusers"));
        assert!(contains_path_confusion("/admin\\realms\\users"));
        assert!(!contains_path_confusion(
            "/admin/realms/example-realm/users"
        ));
    }

    #[tokio::test]
    async fn rejects_path_confusion_vectors() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/admin/realms/%2e%2e/users")
                    .body(axum::body::Body::empty())
                    .expect("request build"),
            )
            .await
            .expect("edge response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
