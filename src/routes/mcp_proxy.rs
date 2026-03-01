use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::proxy::{headers, sse};
use crate::AppState;

/// Extract the bearer token from the Authorization header.
/// Returns `Err(401)` if missing or malformed.
fn extract_bearer_token(headers: &HeaderMap) -> Result<&str, StatusCode> {
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    value
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)
}

/// GET /mcp/:name — SSE streaming proxy
pub async fn mcp_sse(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, impl IntoResponse> {
    let ds = state.find_downstream(&name).ok_or(StatusCode::NOT_FOUND)?;

    let token = extract_bearer_token(&headers)?;
    let (header_name, header_value) = headers::remap_auth_header(&ds.auth_header_format, token);

    tracing::debug!(downstream = %name, downstream_url = %ds.downstream_url, "SSE proxy");

    sse::proxy_sse(
        &ds.downstream_url,
        &header_name,
        &header_value,
        &state.http_client,
    )
    .await
}

/// POST /mcp/:name — JSON-RPC proxy
pub async fn mcp_post(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, impl IntoResponse> {
    let ds = state.find_downstream(&name).ok_or(StatusCode::NOT_FOUND)?;

    let token = extract_bearer_token(&headers)?;
    let (header_name, header_value) = headers::remap_auth_header(&ds.auth_header_format, token);

    tracing::debug!(downstream = %name, downstream_url = %ds.downstream_url, "POST proxy");

    sse::proxy_post(
        &ds.downstream_url,
        &header_name,
        &header_value,
        body,
        &state.http_client,
    )
    .await
}
