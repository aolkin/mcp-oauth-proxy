use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;

/// POST /token/mcp/:name — token exchange and refresh
pub async fn token(Path(_name): Path<String>) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}
