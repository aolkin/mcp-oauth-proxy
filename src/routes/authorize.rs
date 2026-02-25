use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::AppState;

/// GET /authorize/mcp/:name — show authorization page
pub async fn authorize_get(
    State(_state): State<AppState>,
    Path(_name): Path<String>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}

/// POST /authorize/mcp/:name — submit credentials (passthrough)
pub async fn authorize_post(
    State(_state): State<AppState>,
    Path(_name): Path<String>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}

/// GET /callback/mcp/:name — OAuth provider callback (chained OAuth)
pub async fn callback(
    State(_state): State<AppState>,
    Path(_name): Path<String>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}
