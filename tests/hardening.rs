use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::future::IntoFuture;
use std::net::SocketAddr;

fn test_secret() -> String {
    STANDARD.encode([0xAA_u8; 32])
}

fn make_config_toml(proxy_addr: &SocketAddr) -> String {
    format!(
        r#"
[server]
public_url = "http://127.0.0.1:{port}"
state_secret = "{secret}"

[downstream.test]
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
    let state = mcp_oauth_proxy::AppState::new(config, reqwest::Client::new());

    let app = mcp_oauth_proxy::build_router(state);
    tokio::spawn(axum::serve(listener, app).into_future());

    addr
}

fn post_form(client: &reqwest::Client, url: String, body: &str) -> reqwest::RequestBuilder {
    client
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.to_owned())
}

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

#[tokio::test]
async fn test_token_errors_return_rfc6749_json() {
    let addr = start_proxy().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/token/mcp/test");

    // Unknown grant type
    let resp = post_form(&client, url.clone(), "grant_type=invalid_type")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
    assert!(body["error_description"].is_string());

    // authorization_code with missing code
    let resp = post_form(&client, url.clone(), "grant_type=authorization_code")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");

    // authorization_code with garbage encrypted code
    let resp = post_form(
        &client,
        url.clone(),
        "grant_type=authorization_code&code=garbage&code_verifier=abc&redirect_uri=http://x",
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");

    // Unknown downstream also returns JSON
    let resp = post_form(
        &client,
        format!("http://{addr}/token/mcp/nonexistent"),
        "grant_type=authorization_code&code=x",
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn test_authorize_rejects_bad_params() {
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
async fn test_callback_wrong_strategy_rejected() {
    let addr = start_proxy().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/callback/mcp/test?code=x&state=y"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_refresh_on_passthrough_rejected() {
    let addr = start_proxy().await;
    let resp = post_form(
        &reqwest::Client::new(),
        format!("http://{addr}/token/mcp/test"),
        "grant_type=refresh_token&refresh_token=abc",
    )
    .send()
    .await
    .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
}
