use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Form;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::oauth::codes::{self, DownstreamTokens};
use crate::oauth::pkce;
use crate::AppState;

#[derive(Deserialize)]
pub struct TokenForm {
    grant_type: String,
    code: Option<String>,
    code_verifier: Option<String>,
    redirect_uri: Option<String>,
    #[allow(dead_code)]
    client_id: Option<String>,
    #[allow(dead_code)]
    refresh_token: Option<String>,
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> impl IntoResponse {
    (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// POST /token/mcp/:name — token exchange and refresh
pub async fn token(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<TokenForm>,
) -> impl IntoResponse {
    let Some(_ds) = state.find_downstream(&name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown downstream"})),
        )
            .into_response();
    };

    match form.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&state, form).into_response(),
        "refresh_token" => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "refresh_token grant not supported for passthrough strategy",
        )
        .into_response(),
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Supported grant types: authorization_code",
        )
        .into_response(),
    }
}

fn handle_authorization_code(state: &AppState, form: TokenForm) -> impl IntoResponse {
    let Some(code) = &form.code else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code is required",
        )
        .into_response();
    };

    let Some(code_verifier) = &form.code_verifier else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_verifier is required",
        )
        .into_response();
    };

    let Some(redirect_uri) = &form.redirect_uri else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required",
        )
        .into_response();
    };

    let grant = match codes::validate_auth_code(code, &state.state_secret) {
        Ok(g) => g,
        Err(e) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", e).into_response();
        }
    };

    if grant.redirect_uri != *redirect_uri {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri mismatch",
        )
        .into_response();
    }

    if !pkce::verify_pkce(code_verifier, &grant.pkce_challenge) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verification failed",
        )
        .into_response();
    }

    match grant.downstream_tokens {
        DownstreamTokens::Passthrough { access_token } => Json(json!({
            "access_token": access_token,
            "token_type": "Bearer"
        }))
        .into_response(),
        DownstreamTokens::ChainedOAuth {
            access_token,
            refresh_token,
            expires_in,
        } => {
            let mut resp = json!({
                "access_token": access_token,
                "token_type": "Bearer"
            });
            if let Some(rt) = refresh_token {
                resp["refresh_token"] = json!(rt);
            }
            if let Some(ei) = expires_in {
                resp["expires_in"] = json!(ei);
            }
            Json(resp).into_response()
        }
    }
}
