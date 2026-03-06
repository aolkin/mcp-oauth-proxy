use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;
use std::future::IntoFuture;
use std::net::SocketAddr;

fn test_secret() -> String {
    STANDARD.encode([0xAA_u8; 32])
}

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CLAUDE_REDIRECT: &str = "http://localhost:9999/callback";

fn pkce_challenge(verifier: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn mock_mcp_handler(headers: axum::http::HeaderMap) -> axum::response::Response {
    let api_key = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let body = json!({ "tools": ["tool1"], "auth_key": api_key });
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&body).unwrap(),
        ))
        .unwrap()
}

async fn start_mock_mcp() -> SocketAddr {
    let app = Router::new().route("/mcp", get(mock_mcp_handler).post(mock_mcp_handler));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());
    addr
}

fn make_config_toml(mock_addr: &SocketAddr, proxy_addr: &SocketAddr) -> String {
    format!(
        r#"
[server]
public_url = "http://127.0.0.1:{proxy_port}"
state_secret = "{secret}"
auth_code_ttl = 300

[downstream.test-pt]
display_name = "Test Passthrough"
strategy = "passthrough"
downstream_url = "http://127.0.0.1:{mock_port}/mcp"
auth_header_format = "X-API-Key"
auth_hint = "Enter your test API key"
scopes = "read write"
"#,
        proxy_port = proxy_addr.port(),
        mock_port = mock_addr.port(),
        secret = test_secret(),
    )
}

async fn start_proxy(mock_addr: &SocketAddr) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let toml_str = make_config_toml(mock_addr, &proxy_addr);
    let config: mcp_oauth_proxy::config::Config = toml::from_str(&toml_str).unwrap();
    let state = mcp_oauth_proxy::AppState::new(config, reqwest::Client::new());

    let app = mcp_oauth_proxy::build_router(state);
    tokio::spawn(axum::serve(listener, app).into_future());

    proxy_addr
}

#[tokio::test]
async fn test_full_passthrough_flow() {
    let mock_addr = start_mock_mcp().await;
    let proxy_addr = start_proxy(&mock_addr).await;
    let client = no_redirect_client();
    let challenge = pkce_challenge(VERIFIER);

    // 1. Discovery: protected resource metadata
    let resp = client
        .get(format!(
            "http://{proxy_addr}/.well-known/oauth-protected-resource/mcp/test-pt"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["resource"].as_str().unwrap().contains("test-pt"));

    // 2. Discovery: authorization server metadata
    let resp = client
        .get(format!(
            "http://{proxy_addr}/.well-known/oauth-authorization-server/mcp/test-pt"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let meta: serde_json::Value = resp.json().await.unwrap();
    assert!(meta["authorization_endpoint"]
        .as_str()
        .unwrap()
        .contains("/authorize/mcp/test-pt"));
    assert!(meta["token_endpoint"]
        .as_str()
        .unwrap()
        .contains("/token/mcp/test-pt"));
    let grant_types: Vec<&str> = meta["grant_types_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(grant_types.contains(&"authorization_code"));
    assert!(!grant_types.contains(&"refresh_token"));

    // 3. Authorize GET: should return an HTML form (passthrough)
    let resp = client
        .get(format!(
            "http://{proxy_addr}/authorize/mcp/test-pt\
             ?response_type=code\
             &client_id=claude-client\
             &redirect_uri={CLAUDE_REDIRECT}\
             &state=test-state-123\
             &code_challenge={challenge}\
             &code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("Test Passthrough"));
    assert!(html.contains("Enter your test API key"));
    assert!(html.contains("read write"));
    assert!(html.contains(r#"name="token"#));

    // 4. Authorize POST: submit the token form
    let resp = client
        .post(format!("http://{proxy_addr}/authorize/mcp/test-pt"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "token=my-secret-api-key\
             &state=test-state-123\
             &redirect_uri={CLAUDE_REDIRECT}\
             &code_challenge={challenge}\
             &code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with(CLAUDE_REDIRECT));

    let callback_url = url::Url::parse(location).unwrap();
    let returned_state: String = callback_url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .unwrap();
    assert_eq!(returned_state, "test-state-123");
    let proxy_code: String = callback_url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .unwrap();

    // 5. Token exchange with correct PKCE verifier
    let resp = client
        .post(format!("http://{proxy_addr}/token/mcp/test-pt"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code\
             &code={proxy_code}\
             &code_verifier={VERIFIER}\
             &redirect_uri={CLAUDE_REDIRECT}\
             &client_id=claude-client"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["access_token"], "my-secret-api-key");
    assert_eq!(body["token_type"], "Bearer");
    assert!(body.get("refresh_token").is_none());

    // 6. Use the token to make a proxied MCP request
    let resp = client
        .post(format!("http://{proxy_addr}/mcp/test-pt"))
        .header("Authorization", "Bearer my-secret-api-key")
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["auth_key"], "my-secret-api-key");
    assert_eq!(body["tools"][0], "tool1");
}

#[tokio::test]
async fn test_passthrough_wrong_pkce_rejected() {
    let mock_addr = start_mock_mcp().await;
    let proxy_addr = start_proxy(&mock_addr).await;
    let client = no_redirect_client();
    let challenge = pkce_challenge(VERIFIER);

    let resp = client
        .post(format!("http://{proxy_addr}/authorize/mcp/test-pt"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "token=my-secret-api-key\
             &state=s\
             &redirect_uri={CLAUDE_REDIRECT}\
             &code_challenge={challenge}\
             &code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let callback_url = url::Url::parse(location).unwrap();
    let proxy_code: String = callback_url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .unwrap();

    let resp = client
        .post(format!("http://{proxy_addr}/token/mcp/test-pt"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code\
             &code={proxy_code}\
             &code_verifier=wrong-verifier\
             &redirect_uri={CLAUDE_REDIRECT}\
             &client_id=claude-client"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert!(body["error_description"].as_str().unwrap().contains("PKCE"));
}
