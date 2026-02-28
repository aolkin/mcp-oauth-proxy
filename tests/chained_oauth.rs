use axum::extract::{Form, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Mock downstream OAuth server
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockState {
    // Records received token requests for assertions
    token_requests: Arc<Mutex<Vec<TokenRequest>>>,
    refresh_count: Arc<Mutex<u32>>,
    // Controls mock behavior
    fail_token_exchange: Arc<Mutex<bool>>,
    fail_refresh: Arc<Mutex<bool>>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct TokenRequest {
    grant_type: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

async fn mock_authorize() -> impl IntoResponse {
    // The mock authorize endpoint just returns 200 — in a real flow the user
    // would see a consent page. Our tests drive the redirect manually.
    "Mock authorize page"
}

async fn mock_token(
    State(state): State<MockState>,
    Form(form): Form<TokenRequest>,
) -> impl IntoResponse {
    state.token_requests.lock().await.push(form.clone());

    match form.grant_type.as_str() {
        "authorization_code" => {
            if *state.fail_token_exchange.lock().await {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_grant",
                        "error_description": "Bad authorization code"
                    })),
                )
                    .into_response();
            }

            Json(json!({
                "access_token": "downstream-access-token-abc",
                "token_type": "bearer",
                "expires_in": 28800,
                "refresh_token": "downstream-refresh-token-xyz"
            }))
            .into_response()
        }
        "refresh_token" => {
            if *state.fail_refresh.lock().await {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_grant",
                        "error_description": "Refresh token expired"
                    })),
                )
                    .into_response();
            }

            let mut count = state.refresh_count.lock().await;
            *count += 1;
            let n = *count;

            Json(json!({
                "access_token": format!("refreshed-access-token-{n}"),
                "token_type": "bearer",
                "expires_in": 28800,
                "refresh_token": format!("refreshed-refresh-token-{n}")
            }))
            .into_response()
        }
        _ => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": "unsupported_grant_type"})),
        )
            .into_response(),
    }
}

async fn start_mock_downstream() -> (SocketAddr, MockState) {
    let state = MockState {
        token_requests: Arc::new(Mutex::new(Vec::new())),
        refresh_count: Arc::new(Mutex::new(0)),
        fail_token_exchange: Arc::new(Mutex::new(false)),
        fail_refresh: Arc::new(Mutex::new(false)),
    };

    let app = Router::new()
        .route("/authorize", get(mock_authorize))
        .route("/token", post(mock_token))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, app).into_future());

    (addr, state)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_secret() -> String {
    STANDARD.encode([0xAA_u8; 32])
}

fn make_config_toml(mock_addr: &SocketAddr, proxy_addr: &SocketAddr) -> String {
    format!(
        r#"
[server]
public_url = "http://127.0.0.1:{proxy_port}"
state_secret = "{secret}"
auth_code_ttl = 300

[[downstream]]
name = "test-oauth"
display_name = "Test OAuth Provider"
strategy = "chained_oauth"
downstream_url = "http://127.0.0.1:{mock_port}/mcp"
oauth_authorize_url = "http://127.0.0.1:{mock_port}/authorize"
oauth_token_url = "http://127.0.0.1:{mock_port}/token"
oauth_client_id = "test-client-id"
oauth_client_secret = "test-client-secret"
oauth_scopes = "read write"
oauth_supports_refresh = true
"#,
        proxy_port = proxy_addr.port(),
        mock_port = mock_addr.port(),
        secret = test_secret(),
    )
}

async fn start_proxy(mock_addr: &SocketAddr) -> SocketAddr {
    // Bind to get a port, then build config
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let toml_str = make_config_toml(mock_addr, &proxy_addr);
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

    proxy_addr
}

/// Compute a PKCE S256 challenge from a verifier.
fn pkce_challenge(verifier: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_authorize_redirects_to_downstream() {
    let (mock_addr, _mock_state) = start_mock_downstream().await;
    let proxy_addr = start_proxy(&mock_addr).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = pkce_challenge(verifier);

    let resp = client
        .get(format!(
            "http://{proxy_addr}/authorize/mcp/test-oauth\
             ?response_type=code\
             &client_id=claude-client\
             &redirect_uri=http://localhost:9999/callback\
             &state=claude-state-abc\
             &code_challenge={challenge}\
             &code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 303, "should redirect");

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with(&format!("http://127.0.0.1:{}/authorize?", mock_addr.port())),
        "should redirect to downstream authorize URL, got: {location}"
    );
    assert!(
        location.contains("client_id=test-client-id"),
        "should include proxy's client_id"
    );
    assert!(
        location.contains("scope=read+write") || location.contains("scope=read%20write"),
        "should include scopes"
    );
    assert!(
        location.contains("redirect_uri="),
        "should include callback redirect_uri"
    );
    assert!(location.contains("state="), "should include signed state");
    assert!(
        location.contains("response_type=code"),
        "should include response_type=code"
    );
}

#[tokio::test]
async fn test_full_chained_oauth_flow() {
    let (mock_addr, mock_state) = start_mock_downstream().await;
    let proxy_addr = start_proxy(&mock_addr).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = pkce_challenge(verifier);
    let claude_redirect = "http://localhost:9999/callback";
    let claude_state = "claude-state-xyz";

    // Step 1: GET /authorize → should redirect to downstream
    let resp = client
        .get(format!(
            "http://{proxy_addr}/authorize/mcp/test-oauth\
             ?response_type=code\
             &client_id=claude-client\
             &redirect_uri={claude_redirect}\
             &state={claude_state}\
             &code_challenge={challenge}\
             &code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 303);
    let authorize_location = resp.headers().get("location").unwrap().to_str().unwrap();

    // Extract the signed state from the redirect URL
    let url = url::Url::parse(authorize_location).unwrap();
    let signed_state: String = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .unwrap();

    // Step 2: Simulate downstream callback with an authorization code
    let resp = client
        .get(format!(
            "http://{proxy_addr}/callback/mcp/test-oauth\
             ?code=downstream-auth-code-123\
             &state={signed_state}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 303, "callback should redirect to Claude");
    let callback_location = resp.headers().get("location").unwrap().to_str().unwrap();

    // Verify it redirects back to Claude's redirect_uri
    assert!(
        callback_location.starts_with(claude_redirect),
        "should redirect to Claude's redirect_uri, got: {callback_location}"
    );

    // Extract the proxy auth code and Claude's original state
    let callback_url = url::Url::parse(callback_location).unwrap();
    let proxy_code: String = callback_url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .unwrap();
    let returned_state: String = callback_url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .unwrap();

    assert_eq!(
        returned_state, claude_state,
        "should return Claude's original state"
    );

    // Verify mock received the token exchange request
    let token_reqs = mock_state.token_requests.lock().await;
    assert_eq!(token_reqs.len(), 1);
    assert_eq!(token_reqs[0].grant_type, "authorization_code");
    assert_eq!(
        token_reqs[0].code.as_deref(),
        Some("downstream-auth-code-123")
    );
    assert_eq!(token_reqs[0].client_id.as_deref(), Some("test-client-id"));
    assert_eq!(
        token_reqs[0].client_secret.as_deref(),
        Some("test-client-secret")
    );
    drop(token_reqs);

    // Step 3: POST /token with authorization_code grant
    let resp = client
        .post(format!("http://{proxy_addr}/token/mcp/test-oauth"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code\
             &code={proxy_code}\
             &code_verifier={verifier}\
             &redirect_uri={claude_redirect}\
             &client_id=claude-client"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["access_token"], "downstream-access-token-abc");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["refresh_token"], "downstream-refresh-token-xyz");
    assert_eq!(body["expires_in"], 28800);
}

#[tokio::test]
async fn test_refresh_token_flow() {
    let (mock_addr, _mock_state) = start_mock_downstream().await;
    let proxy_addr = start_proxy(&mock_addr).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // POST /token with refresh_token grant
    let resp = client
        .post(format!("http://{proxy_addr}/token/mcp/test-oauth"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(
            "grant_type=refresh_token\
             &refresh_token=downstream-refresh-token-xyz\
             &client_id=claude-client",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["access_token"], "refreshed-access-token-1");
    assert_eq!(body["refresh_token"], "refreshed-refresh-token-1");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 28800);
}

#[tokio::test]
async fn test_tampered_state_rejected() {
    let (mock_addr, _mock_state) = start_mock_downstream().await;
    let proxy_addr = start_proxy(&mock_addr).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Call callback with a tampered state
    let resp = client
        .get(format!(
            "http://{proxy_addr}/callback/mcp/test-oauth\
             ?code=some-code\
             &state=tampered.invalid"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Invalid or expired state"));
}

#[tokio::test]
async fn test_expired_state_rejected() {
    let (mock_addr, _mock_state) = start_mock_downstream().await;
    let proxy_addr = start_proxy(&mock_addr).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Create a signed state with an expired timestamp
    let secret = vec![0xAA_u8; 32];
    let expired_state_payload = json!({
        "claude_state": "test-state",
        "claude_redirect_uri": "http://localhost/callback",
        "pkce_challenge": "test-challenge",
        "pkce_method": "S256",
        "exp": 0,  // expired
    });
    let expired_signed = mcp_oauth_proxy::oauth::state::sign_state(&expired_state_payload, &secret);

    let resp = client
        .get(format!(
            "http://{proxy_addr}/callback/mcp/test-oauth\
             ?code=some-code\
             &state={expired_signed}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Invalid or expired state"));
}

#[tokio::test]
async fn test_downstream_token_exchange_failure() {
    let (mock_addr, mock_state) = start_mock_downstream().await;
    let proxy_addr = start_proxy(&mock_addr).await;

    // Set mock to fail token exchange
    *mock_state.fail_token_exchange.lock().await = true;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = pkce_challenge(verifier);

    // Step 1: Authorize
    let resp = client
        .get(format!(
            "http://{proxy_addr}/authorize/mcp/test-oauth\
             ?response_type=code\
             &client_id=claude-client\
             &redirect_uri=http://localhost:9999/callback\
             &state=test-state\
             &code_challenge={challenge}\
             &code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();

    let authorize_location = resp.headers().get("location").unwrap().to_str().unwrap();
    let url = url::Url::parse(authorize_location).unwrap();
    let signed_state: String = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .unwrap();

    // Step 2: Callback — should fail because mock returns error
    let resp = client
        .get(format!(
            "http://{proxy_addr}/callback/mcp/test-oauth\
             ?code=bad-code\
             &state={signed_state}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 502);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Token exchange failed"));
}

#[tokio::test]
async fn test_downstream_refresh_failure() {
    let (mock_addr, mock_state) = start_mock_downstream().await;
    let proxy_addr = start_proxy(&mock_addr).await;

    // Set mock to fail refresh
    *mock_state.fail_refresh.lock().await = true;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let resp = client
        .post(format!("http://{proxy_addr}/token/mcp/test-oauth"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(
            "grant_type=refresh_token\
             &refresh_token=expired-token\
             &client_id=claude-client",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert!(body["error_description"]
        .as_str()
        .unwrap()
        .contains("re-authorize"));
}

#[tokio::test]
async fn test_well_known_advertises_refresh_for_chained() {
    let (mock_addr, _mock_state) = start_mock_downstream().await;
    let proxy_addr = start_proxy(&mock_addr).await;

    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "http://{proxy_addr}/.well-known/oauth-authorization-server/mcp/test-oauth"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    let grant_types = body["grant_types_supported"].as_array().unwrap();
    let grant_types: Vec<&str> = grant_types.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(grant_types.contains(&"authorization_code"));
    assert!(grant_types.contains(&"refresh_token"));
}

#[tokio::test]
async fn test_callback_missing_params() {
    let (mock_addr, _mock_state) = start_mock_downstream().await;
    let proxy_addr = start_proxy(&mock_addr).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Missing code
    let resp = client
        .get(format!(
            "http://{proxy_addr}/callback/mcp/test-oauth?state=something"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Missing state
    let resp = client
        .get(format!(
            "http://{proxy_addr}/callback/mcp/test-oauth?code=something"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_downstream_error_in_callback() {
    let (mock_addr, _mock_state) = start_mock_downstream().await;
    let proxy_addr = start_proxy(&mock_addr).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Downstream provider returned an error
    let resp = client
        .get(format!(
            "http://{proxy_addr}/callback/mcp/test-oauth\
             ?error=access_denied\
             &error_description=User+denied+access"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 502);
    let body = resp.text().await.unwrap();
    assert!(body.contains("User denied access"));
}

#[tokio::test]
async fn test_pkce_verification_on_chained_code() {
    let (mock_addr, _mock_state) = start_mock_downstream().await;
    let proxy_addr = start_proxy(&mock_addr).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = pkce_challenge(verifier);
    let claude_redirect = "http://localhost:9999/callback";

    // Full flow: authorize → callback → get proxy code
    let resp = client
        .get(format!(
            "http://{proxy_addr}/authorize/mcp/test-oauth\
             ?response_type=code\
             &client_id=claude-client\
             &redirect_uri={claude_redirect}\
             &state=test-state\
             &code_challenge={challenge}\
             &code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();

    let authorize_location = resp.headers().get("location").unwrap().to_str().unwrap();
    let url = url::Url::parse(authorize_location).unwrap();
    let signed_state: String = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .unwrap();

    let resp = client
        .get(format!(
            "http://{proxy_addr}/callback/mcp/test-oauth\
             ?code=downstream-code\
             &state={signed_state}"
        ))
        .send()
        .await
        .unwrap();

    let callback_location = resp.headers().get("location").unwrap().to_str().unwrap();
    let callback_url = url::Url::parse(callback_location).unwrap();
    let proxy_code: String = callback_url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .unwrap();

    // Try with wrong verifier — should fail PKCE
    let resp = client
        .post(format!("http://{proxy_addr}/token/mcp/test-oauth"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code\
             &code={proxy_code}\
             &code_verifier=wrong-verifier\
             &redirect_uri={claude_redirect}\
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
