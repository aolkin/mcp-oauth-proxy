use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

async fn start_mock_downstream() -> String {
    let app = Router::new()
        .route("/sse", get(mock_sse_handler))
        .route("/rpc", post(mock_post_handler));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://127.0.0.1:{port}")
}

async fn mock_sse_handler(headers: axum::http::HeaderMap) -> axum::response::Response {
    let api_key = headers.get("X-API-Key").and_then(|v| v.to_str().ok());

    let events = if api_key == Some("test-token-123") {
        "data: {\"event\":\"hello\"}\n\ndata: {\"event\":\"world\"}\n\n"
    } else if headers.get("authorization").is_some() {
        "data: {\"event\":\"bearer-ok\"}\n\n"
    } else {
        return axum::response::Response::builder()
            .status(401)
            .body(axum::body::Body::from("unauthorized"))
            .unwrap();
    };

    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .body(axum::body::Body::from(events))
        .unwrap()
}

async fn mock_post_handler(
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let api_key = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let body_str = String::from_utf8_lossy(&body);
    let response = serde_json::json!({
        "echo": serde_json::from_str::<serde_json::Value>(&body_str).unwrap_or(serde_json::Value::Null),
        "auth_key": api_key,
    });

    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&response).unwrap(),
        ))
        .unwrap()
}

fn build_proxy_app(downstream_url: &str) -> Router {
    use base64::Engine;

    let secret = base64::engine::general_purpose::STANDARD.encode([0xAA; 32]);

    let toml_str = format!(
        r#"
[server]
public_url = "http://localhost:9999"
state_secret = "{secret}"

[[downstream]]
name = "test-sse"
display_name = "Test SSE"
strategy = "passthrough"
downstream_url = "{downstream_url}/sse"
auth_header_format = "X-API-Key"

[[downstream]]
name = "test-bearer"
display_name = "Test Bearer"
strategy = "passthrough"
downstream_url = "{downstream_url}/sse"
auth_header_format = "Bearer"

[[downstream]]
name = "test-rpc"
display_name = "Test RPC"
strategy = "passthrough"
downstream_url = "{downstream_url}/rpc"
auth_header_format = "X-API-Key"
"#
    );

    let config: mcp_oauth_proxy::config::Config = toml::from_str(&toml_str).unwrap();
    let state_secret = base64::engine::general_purpose::STANDARD
        .decode(&config.server.state_secret)
        .unwrap();

    let state = mcp_oauth_proxy::AppState::new(config, state_secret, reqwest::Client::new());

    Router::new()
        .route(
            "/mcp/{name}",
            get(mcp_oauth_proxy::routes::mcp_proxy::mcp_sse)
                .post(mcp_oauth_proxy::routes::mcp_proxy::mcp_post),
        )
        .with_state(state)
}

async fn start_proxy(downstream_url: &str) -> String {
    let app = build_proxy_app(downstream_url);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://127.0.0.1:{port}")
}

#[tokio::test]
async fn test_sse_proxy_streams_events() {
    let downstream = start_mock_downstream().await;
    let proxy = start_proxy(&downstream).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{proxy}/mcp/test-sse"))
        .header("Authorization", "Bearer test-token-123")
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/event-stream"
    );

    let body = resp.text().await.unwrap();
    assert!(body.contains(r#"{"event":"hello"}"#));
    assert!(body.contains(r#"{"event":"world"}"#));
}

#[tokio::test]
async fn test_sse_proxy_bearer_format() {
    let downstream = start_mock_downstream().await;
    let proxy = start_proxy(&downstream).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{proxy}/mcp/test-bearer"))
        .header("Authorization", "Bearer some-token")
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains(r#"{"event":"bearer-ok"}"#));
}

#[tokio::test]
async fn test_post_proxy_forwards_body_and_remaps_auth() {
    let downstream = start_mock_downstream().await;
    let proxy = start_proxy(&downstream).await;

    let rpc_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{proxy}/mcp/test-rpc"))
        .header("Authorization", "Bearer test-token-123")
        .header("Content-Type", "application/json")
        .json(&rpc_body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["auth_key"], "test-token-123");
    assert_eq!(body["echo"]["method"], "tools/list");
    assert_eq!(body["echo"]["id"], 1);
}

#[tokio::test]
async fn test_auth_errors_return_401() {
    let downstream = start_mock_downstream().await;
    let proxy = start_proxy(&downstream).await;

    let client = reqwest::Client::new();

    // No auth header
    let resp = client
        .get(format!("{proxy}/mcp/test-sse"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Wrong auth scheme
    let resp = client
        .get(format!("{proxy}/mcp/test-sse"))
        .header("Authorization", "Basic abc123")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_unknown_downstream_returns_404() {
    let downstream = start_mock_downstream().await;
    let proxy = start_proxy(&downstream).await;

    let resp = reqwest::Client::new()
        .get(format!("{proxy}/mcp/nonexistent"))
        .header("Authorization", "Bearer some-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_unreachable_downstream_returns_502() {
    let proxy = start_proxy("http://127.0.0.1:1").await;

    let resp = reqwest::Client::new()
        .get(format!("{proxy}/mcp/test-sse"))
        .header("Authorization", "Bearer some-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);
}
