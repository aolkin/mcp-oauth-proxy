use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;

fn test_secret() -> String {
    STANDARD.encode([0xAA_u8; 32])
}

fn make_config_toml(proxy_addr: &SocketAddr) -> String {
    format!(
        r#"
[server]
public_url = "http://127.0.0.1:{port}"
state_secret = "{secret}"

[[downstream]]
name = "test"
display_name = "Test Service"
strategy = "passthrough"
downstream_url = "http://127.0.0.1:1/mcp"
"#,
        port = proxy_addr.port(),
        secret = test_secret(),
    )
}

async fn start_proxy() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let toml_str = make_config_toml(&addr);
    let config: mcp_oauth_proxy::config::Config = toml::from_str(&toml_str).unwrap();

    let state_secret = STANDARD
        .decode(&config.server.state_secret)
        .expect("base64 decode");

    let state = mcp_oauth_proxy::AppState {
        config: Arc::new(config),
        state_secret,
        http_client: reqwest::Client::new(),
    };

    let app = mcp_oauth_proxy::build_router(state);
    tokio::spawn(axum::serve(listener, app).into_future());

    addr
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_health_endpoint() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "OK");
}

// ---------------------------------------------------------------------------
// Token endpoint: malformed input
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_token_empty_body() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/token/mcp/test"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("")
        .send()
        .await
        .unwrap();

    // Should return 4xx, not panic
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn test_token_garbage_body() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/token/mcp/test"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("not=valid&form=data&but=missing&grant_type")
        .send()
        .await
        .unwrap();

    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn test_token_json_body_rejected() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/token/mcp/test"))
        .header("Content-Type", "application/json")
        .body(r#"{"grant_type":"authorization_code"}"#)
        .send()
        .await
        .unwrap();

    // Should return error, not panic
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn test_token_invalid_grant_type_returns_json() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/token/mcp/test"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("grant_type=invalid_type")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
    assert!(body["error_description"].is_string());
}

#[tokio::test]
async fn test_token_missing_code_returns_json() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/token/mcp/test"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("grant_type=authorization_code")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn test_token_garbage_code_returns_json() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/token/mcp/test"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("grant_type=authorization_code&code=not-a-real-code&code_verifier=abc&redirect_uri=http://x")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_token_unknown_downstream_returns_json() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/token/mcp/nonexistent"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("grant_type=authorization_code&code=x")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].is_string());
}

// ---------------------------------------------------------------------------
// Authorize endpoint: malformed input
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_authorize_missing_params() {
    let addr = start_proxy().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // No query params at all
    let resp = client
        .get(format!("http://{addr}/authorize/mcp/test"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Wrong response_type
    let resp = client
        .get(format!(
            "http://{addr}/authorize/mcp/test?response_type=token&redirect_uri=http://x&state=s&code_challenge=c&code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_authorize_unknown_downstream() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/authorize/mcp/nonexistent?response_type=code&redirect_uri=http://x&state=s&code_challenge=c&code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// MCP proxy: auth errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_no_auth_header() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/mcp/test"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_mcp_wrong_auth_scheme() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/mcp/test"))
        .header("Authorization", "Basic dXNlcjpwYXNz")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ---------------------------------------------------------------------------
// Callback: malformed input
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_callback_passthrough_rejected() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/callback/mcp/test?code=x&state=y"))
        .send()
        .await
        .unwrap();
    // "test" is passthrough, not chained_oauth
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_callback_unknown_downstream() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/callback/mcp/nonexistent?code=x&state=y"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Well-known: unknown downstream
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_well_known_unknown_downstream() {
    let addr = start_proxy().await;

    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/.well-known/oauth-protected-resource/mcp/nonexistent"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/.well-known/oauth-authorization-server/mcp/nonexistent"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Passthrough: refresh not supported
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_refresh_on_passthrough_rejected() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/token/mcp/test"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("grant_type=refresh_token&refresh_token=abc")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
}
