use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;

/// GET /.well-known/oauth-protected-resource/mcp/:name
pub async fn protected_resource(Path(_name): Path<String>) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}

/// GET /.well-known/oauth-authorization-server/mcp/:name
pub async fn authorization_server(Path(_name): Path<String>) -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "not yet implemented")
}
