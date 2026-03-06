use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::proxy::{headers, sse};
use crate::AppState;

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, [("WWW-Authenticate", "Bearer")]).into_response()
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// GET /mcp/:name — SSE streaming proxy
pub async fn mcp_sse(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let ds = state
        .find_downstream(&name)
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    let token = extract_bearer_token(&headers).ok_or_else(unauthorized)?;
    let (header_name, header_value) = headers::remap_auth_header(&ds.auth_header_format, token);

    tracing::debug!(downstream = %name, downstream_url = %ds.downstream_url, "SSE proxy");

    sse::proxy_sse(
        &ds.downstream_url,
        &header_name,
        &header_value,
        &state.http_client,
    )
    .await
    .map_err(IntoResponse::into_response)
}

/// POST /mcp/:name — JSON-RPC proxy
pub async fn mcp_post(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let ds = state
        .find_downstream(&name)
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    let token = extract_bearer_token(&headers).ok_or_else(unauthorized)?;
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
    .map_err(IntoResponse::into_response)
}
