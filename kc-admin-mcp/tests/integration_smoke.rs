use std::env;

use reqwest::StatusCode;
use serde_json::json;

#[tokio::test]
async fn mcp_prm_smoke() {
    let base = match env::var("KC_IT_MCP_URL") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("KC_IT_MCP_URL not set; skipping MCP smoke test");
            return;
        }
    };

    let url = format!(
        "{}/.well-known/oauth-protected-resource/mcp",
        base.trim_end_matches('/')
    );
    let response = reqwest::get(url).await.expect("prm request");
    assert!(response.status().is_success());
}

#[tokio::test]
async fn mcp_authorization_server_metadata_smoke() {
    let base = match env::var("KC_IT_MCP_URL") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("KC_IT_MCP_URL not set; skipping auth metadata smoke test");
            return;
        }
    };

    let url = format!(
        "{}/.well-known/oauth-authorization-server/mcp",
        base.trim_end_matches('/')
    );
    let response = reqwest::get(url).await.expect("auth metadata request");
    assert!(response.status().is_success());
    let payload: serde_json::Value = response.json().await.expect("auth metadata json");
    assert!(payload["issuer"].is_string());
    assert!(payload["authorization_endpoint"].is_string());
    assert!(payload["token_endpoint"].is_string());
    assert!(payload["device_authorization_endpoint"].is_string());
    assert!(payload["grant_types_supported"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| {
            item.as_str() == Some("urn:ietf:params:oauth:grant-type:device_code")
        })));
}

#[tokio::test]
async fn mcp_requires_auth() {
    let base = match env::var("KC_IT_MCP_URL") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("KC_IT_MCP_URL not set; skipping MCP auth test");
            return;
        }
    };

    let url = format!("{}/mcp", base.trim_end_matches('/'));
    let response = reqwest::get(url).await.expect("mcp request");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore]
async fn mcp_accepts_valid_token() {
    let base = env::var("KC_IT_MCP_URL").expect("KC_IT_MCP_URL not set");
    let token = env::var("KC_IT_TOKEN").expect("KC_IT_TOKEN not set");

    let url = format!("{}/mcp", base.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let response = client
        .post(url)
        .bearer_auth(token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .send()
        .await
        .expect("initialize request");

    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}
