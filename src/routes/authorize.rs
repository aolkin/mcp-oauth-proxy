use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use serde::Deserialize;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::chained_oauth;
use crate::config::StrategyConfig;
use crate::oauth::codes::{self, DownstreamTokens};
use crate::oauth::state;
use crate::AppState;

const OAUTH_STATE_TTL_SECS: u64 = 600;

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    response_type: Option<String>,
    #[allow(dead_code)]
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    #[allow(dead_code)]
    scope: Option<String>,
}

/// GET /authorize/mcp/:name — show authorization page
pub async fn authorize_get(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(params): Query<AuthorizeQuery>,
) -> impl IntoResponse {
    let Some(ds) = state.find_downstream(&name) else {
        return (StatusCode::NOT_FOUND, "Unknown downstream").into_response();
    };

    if params.response_type.as_deref() != Some("code") {
        return (StatusCode::BAD_REQUEST, "response_type must be 'code'").into_response();
    }

    let Some(redirect_uri) = &params.redirect_uri else {
        return (StatusCode::BAD_REQUEST, "redirect_uri is required").into_response();
    };

    let Some(oauth_state) = &params.state else {
        return (StatusCode::BAD_REQUEST, "state is required").into_response();
    };

    let Some(code_challenge) = &params.code_challenge else {
        return (StatusCode::BAD_REQUEST, "code_challenge is required").into_response();
    };

    if params.code_challenge_method.as_deref() != Some("S256") {
        return (
            StatusCode::BAD_REQUEST,
            "code_challenge_method must be 'S256'",
        )
            .into_response();
    }

    tracing::info!(downstream = %name, strategy = ?ds.strategy, "Authorize request");

    match &ds.strategy {
        StrategyConfig::Passthrough { auth_hint } => {
            let auth_hint = if auth_hint.is_empty() {
                "Enter your API token or key for this service.".to_string()
            } else {
                html_escape(auth_hint)
            };

            let scopes_html = if ds.scopes.is_empty() {
                String::new()
            } else {
                format!(
                    r#"<p style="color:#666;font-size:0.9em">Required scopes: <code>{}</code></p>"#,
                    html_escape(&ds.scopes)
                )
            };

            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize — {display_name}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 20px; background: #f5f5f5; }}
    .card {{ background: white; border-radius: 8px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
    h1 {{ font-size: 1.4em; margin: 0 0 8px 0; }}
    .hint {{ color: #666; margin: 0 0 20px 0; }}
    label {{ display: block; font-weight: 600; margin-bottom: 6px; }}
    input[type="password"] {{ width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 1em; box-sizing: border-box; }}
    button {{ margin-top: 16px; width: 100%; padding: 12px; background: #2563eb; color: white; border: none; border-radius: 4px; font-size: 1em; cursor: pointer; }}
    button:hover {{ background: #1d4ed8; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{display_name}</h1>
    <p class="hint">{auth_hint}</p>
    {scopes_html}
    <form method="POST">
      <input type="hidden" name="state" value="{state_val}">
      <input type="hidden" name="redirect_uri" value="{redirect_uri_val}">
      <input type="hidden" name="code_challenge" value="{code_challenge_val}">
      <input type="hidden" name="code_challenge_method" value="S256">
      <label for="token">API Token</label>
      <input type="password" id="token" name="token" required autofocus placeholder="Paste your token here">
      <button type="submit">Authorize</button>
    </form>
  </div>
</body>
</html>"#,
                display_name = html_escape(&ds.display_name),
                auth_hint = auth_hint,
                scopes_html = scopes_html,
                state_val = html_escape(oauth_state),
                redirect_uri_val = html_escape(redirect_uri),
                code_challenge_val = html_escape(code_challenge),
            );

            Html(html).into_response()
        }
        StrategyConfig::ChainedOauth {
            oauth_authorize_url,
            oauth_client_id,
            oauth_scopes,
            ..
        } => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let state_blob = json!({
                "claude_state": oauth_state,
                "claude_redirect_uri": redirect_uri,
                "pkce_challenge": code_challenge,
                "pkce_method": "S256",
                "exp": now + OAUTH_STATE_TTL_SECS,
            });

            let signed_state = state::sign_state(&state_blob, &state.state_secret);

            let callback_url = format!(
                "{}/callback/mcp/{}",
                state.config.server.public_url, ds.name
            );

            let mut redirect_url = format!(
                "{}?response_type=code&client_id={}&redirect_uri={}&state={}",
                oauth_authorize_url,
                urlencoding::encode(oauth_client_id),
                urlencoding::encode(&callback_url),
                urlencoding::encode(&signed_state),
            );

            if !oauth_scopes.is_empty() {
                redirect_url.push_str(&format!("&scope={}", urlencoding::encode(oauth_scopes)));
            }

            Redirect::to(&redirect_url).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct AuthorizeForm {
    token: String,
    state: String,
    redirect_uri: String,
    code_challenge: String,
    #[allow(dead_code)]
    code_challenge_method: String,
}

/// POST /authorize/mcp/:name — submit credentials (passthrough)
pub async fn authorize_post(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<AuthorizeForm>,
) -> impl IntoResponse {
    let Some(ds) = state.find_downstream(&name) else {
        return (StatusCode::NOT_FOUND, "Unknown downstream").into_response();
    };

    if !matches!(ds.strategy, StrategyConfig::Passthrough { .. }) {
        return (
            StatusCode::BAD_REQUEST,
            "POST authorize only supported for passthrough strategy",
        )
            .into_response();
    }

    if form.token.is_empty() {
        return (StatusCode::BAD_REQUEST, "token is required").into_response();
    }

    let code = match codes::create_auth_code(
        DownstreamTokens::Passthrough {
            access_token: form.token,
        },
        &form.code_challenge,
        &form.redirect_uri,
        state.config.server.auth_code_ttl,
        &state.state_secret,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create auth code: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    tracing::info!(downstream = %name, "Auth code issued (passthrough)");

    let redirect_url = format!(
        "{}?code={}&state={}",
        form.redirect_uri,
        urlencoding::encode(&code),
        urlencoding::encode(&form.state),
    );

    Redirect::to(&redirect_url).into_response()
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// GET /callback/mcp/:name — OAuth provider callback (chained OAuth)
pub async fn callback(
    State(app): State<AppState>,
    Path(name): Path<String>,
    Query(params): Query<CallbackQuery>,
) -> impl IntoResponse {
    let Some(ds) = app.find_downstream(&name) else {
        return (StatusCode::NOT_FOUND, "Unknown downstream").into_response();
    };

    let StrategyConfig::ChainedOauth {
        oauth_token_url,
        oauth_client_id,
        oauth_client_secret,
        oauth_token_accept,
        ..
    } = &ds.strategy
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Callback only supported for chained_oauth strategy",
        )
            .into_response();
    };

    if let Some(error) = &params.error {
        let desc = params
            .error_description
            .as_deref()
            .unwrap_or("Unknown error");
        tracing::error!(
            downstream = %ds.name,
            error = %error,
            description = %desc,
            "Downstream OAuth provider returned an error"
        );
        return (
            StatusCode::BAD_GATEWAY,
            format!("Downstream authorization failed: {desc}"),
        )
            .into_response();
    }

    let Some(downstream_code) = &params.code else {
        return (StatusCode::BAD_REQUEST, "Missing code parameter").into_response();
    };

    let Some(signed_state) = &params.state else {
        return (StatusCode::BAD_REQUEST, "Missing state parameter").into_response();
    };

    let Some(state_payload) = state::verify_state(signed_state, &app.state_secret) else {
        return (StatusCode::BAD_REQUEST, "Invalid or expired state").into_response();
    };

    let (Some(claude_state), Some(claude_redirect_uri), Some(pkce_challenge)) = (
        state_payload["claude_state"].as_str(),
        state_payload["claude_redirect_uri"].as_str(),
        state_payload["pkce_challenge"].as_str(),
    ) else {
        return (StatusCode::BAD_REQUEST, "Malformed state payload").into_response();
    };

    let callback_url = format!("{}/callback/mcp/{}", app.config.server.public_url, name);

    let body = match chained_oauth::post_downstream_token(
        &app.http_client,
        oauth_token_url,
        oauth_token_accept,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", oauth_client_id.as_str()),
            ("client_secret", oauth_client_secret.as_str()),
            ("code", downstream_code),
            ("redirect_uri", callback_url.as_str()),
        ],
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                downstream = %ds.name,
                error = %e,
                "Failed to exchange downstream authorization code"
            );
            return (
                StatusCode::BAD_GATEWAY,
                format!("Token exchange failed: {e}"),
            )
                .into_response();
        }
    };

    let access_token = match body["access_token"].as_str() {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                "Missing access_token in downstream response",
            )
                .into_response();
        }
    };

    let tokens = DownstreamTokens::ChainedOAuth {
        access_token,
        refresh_token: body["refresh_token"].as_str().map(String::from),
        expires_in: body["expires_in"].as_u64(),
    };

    let code = match codes::create_auth_code(
        tokens,
        pkce_challenge,
        claude_redirect_uri,
        app.config.server.auth_code_ttl,
        &app.state_secret,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create auth code: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    tracing::info!(downstream = %name, "Auth code issued (chained OAuth callback)");

    let redirect_url = format!(
        "{}?code={}&state={}",
        claude_redirect_uri,
        urlencoding::encode(&code),
        urlencoding::encode(claude_state),
    );

    Redirect::to(&redirect_url).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
