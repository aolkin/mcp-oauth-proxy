use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::AppState;

/// POST /token/mcp/:name — token exchange and refresh
pub async fn token(State(_state): State<AppState>, Path(_name): Path<String>) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}
