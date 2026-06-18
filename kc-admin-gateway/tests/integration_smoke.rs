use std::env;

#[tokio::test]
async fn gateway_health_smoke() {
    let base = match env::var("KC_IT_GATEWAY_URL") {
        Ok(value) => value,
        Err(_) => {
            eprintln!("KC_IT_GATEWAY_URL not set; skipping gateway smoke test");
            return;
        }
    };

    let url = format!("{}/health", base.trim_end_matches('/'));
    let response = reqwest::get(url).await.expect("health request");
    assert!(response.status().is_success());
}
