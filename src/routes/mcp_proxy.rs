use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::AppState;

/// GET /mcp/:name — SSE streaming proxy
pub async fn mcp_sse(
    State(_state): State<AppState>,
    Path(_name): Path<String>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}

/// POST /mcp/:name — JSON-RPC proxy
pub async fn mcp_post(
    State(_state): State<AppState>,
    Path(_name): Path<String>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}
