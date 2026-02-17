use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;

/// GET /authorize/mcp/:name — show authorization page
pub async fn authorize_get(Path(_name): Path<String>) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}

/// POST /authorize/mcp/:name — submit credentials (passthrough)
pub async fn authorize_post(Path(_name): Path<String>) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}

/// GET /callback/mcp/:name — OAuth provider callback (chained OAuth)
pub async fn callback(Path(_name): Path<String>) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}
