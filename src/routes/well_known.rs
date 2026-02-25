use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::AppState;

/// GET /.well-known/oauth-protected-resource/mcp/:name
pub async fn protected_resource(
    State(_state): State<AppState>,
    Path(_name): Path<String>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}

/// GET /.well-known/oauth-authorization-server/mcp/:name
pub async fn authorization_server(
    State(_state): State<AppState>,
    Path(_name): Path<String>,
) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}
