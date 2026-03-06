use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::config::StrategyConfig;
use crate::AppState;

/// GET /.well-known/oauth-protected-resource/mcp/:name
pub async fn protected_resource(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if state.find_downstream(&name).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown downstream"})),
        )
            .into_response();
    }

    let resource = format!("{}/mcp/{}", state.config.server.public_url, name);

    Json(json!({
        "resource": resource,
        "authorization_servers": [resource]
    }))
    .into_response()
}

/// GET /.well-known/oauth-authorization-server/mcp/:name
pub async fn authorization_server(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let Some(ds) = state.find_downstream(&name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown downstream"})),
        )
            .into_response();
    };

    let public = &state.config.server.public_url;
    let issuer = format!("{public}/mcp/{}", name);
    let authorization_endpoint = format!("{public}/authorize/mcp/{}", name);
    let token_endpoint = format!("{public}/token/mcp/{}", name);

    let supports_refresh = matches!(
        &ds.strategy,
        StrategyConfig::ChainedOauth { oauth } if oauth.oauth_supports_refresh
    );
    let grant_types = if supports_refresh {
        json!(["authorization_code", "refresh_token"])
    } else {
        json!(["authorization_code"])
    };

    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "response_types_supported": ["code"],
        "grant_types_supported": grant_types,
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"]
    }))
    .into_response()
}
