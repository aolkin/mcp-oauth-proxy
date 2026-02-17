use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;

/// GET /mcp/:name — SSE streaming proxy
pub async fn mcp_sse(Path(_name): Path<String>) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}

/// POST /mcp/:name — JSON-RPC proxy
pub async fn mcp_post(Path(_name): Path<String>) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}
