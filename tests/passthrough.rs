use base64::engine::general_purpose::STANDARD;
use base64::Engine;
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

async fn start_proxy() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let toml_str = format!(
        r#"
[server]
public_url = "http://127.0.0.1:{proxy_port}"
state_secret = "{secret}"
auth_code_ttl = 300

[downstream.test-pt]
display_name = "Test Passthrough"
strategy = "passthrough"
downstream_url = "http://127.0.0.1:1/unused"
auth_header_format = "X-API-Key"
auth_hint = "Enter your test API key"
scopes = "read write"
"#,
        proxy_port = proxy_addr.port(),
        secret = test_secret(),
    );

    let config: mcp_oauth_proxy::config::Config = toml::from_str(&toml_str).unwrap();
    let state = mcp_oauth_proxy::AppState::new(config, reqwest::Client::new());

    let app = mcp_oauth_proxy::build_router(state);
    tokio::spawn(axum::serve(listener, app).into_future());

    proxy_addr
}

fn extract_code_from_redirect(location: &str) -> String {
    let url = url::Url::parse(location).unwrap();
    url.query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .unwrap()
}

fn authorize_post_body(challenge: &str) -> String {
    format!(
        "token=my-secret-api-key\
         &state=s\
         &redirect_uri={CLAUDE_REDIRECT}\
         &code_challenge={challenge}\
         &code_challenge_method=S256"
    )
}

#[tokio::test]
async fn test_passthrough_authorize_and_token_exchange() {
    let proxy_addr = start_proxy().await;
    let client = no_redirect_client();
    let challenge = pkce_challenge(VERIFIER);

    // Authorize POST: submit token via passthrough form
    let resp = client
        .post(format!("http://{proxy_addr}/authorize/mcp/test-pt"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(authorize_post_body(&challenge))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with(CLAUDE_REDIRECT));
    let code = extract_code_from_redirect(location);

    // Token exchange: decrypt code, verify PKCE, return original token
    let resp = client
        .post(format!("http://{proxy_addr}/token/mcp/test-pt"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code\
             &code={code}\
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
}
