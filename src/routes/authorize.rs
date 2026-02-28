use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use serde::Deserialize;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::chained_oauth;
use crate::config::Strategy;
use crate::oauth::codes::{self, DownstreamTokens};
use crate::oauth::state;
use crate::AppState;

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

    match ds.strategy {
        Strategy::Passthrough => {
            let auth_hint = if ds.auth_hint.is_empty() {
                "Enter your API token or key for this service.".to_string()
            } else {
                html_escape(&ds.auth_hint)
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
        Strategy::ChainedOauth => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let state_blob = json!({
                "claude_state": oauth_state,
                "claude_redirect_uri": redirect_uri,
                "pkce_challenge": code_challenge,
                "pkce_method": "S256",
                "exp": now + 600,
            });

            let signed_state = state::sign_state(&state_blob, &state.state_secret);

            let callback_url = format!(
                "{}/callback/mcp/{}",
                state.config.server.public_url, ds.name
            );

            let mut redirect_url = format!(
                "{}?response_type=code&client_id={}&redirect_uri={}&state={}",
                ds.oauth_authorize_url,
                urlencoding::encode(&ds.oauth_client_id),
                urlencoding::encode(&callback_url),
                urlencoding::encode(&signed_state),
            );

            if !ds.oauth_scopes.is_empty() {
                redirect_url.push_str(&format!("&scope={}", urlencoding::encode(&ds.oauth_scopes)));
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

    if ds.strategy != Strategy::Passthrough {
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

    if ds.strategy != Strategy::ChainedOauth {
        return (
            StatusCode::BAD_REQUEST,
            "Callback only supported for chained_oauth strategy",
        )
            .into_response();
    }

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

    let tokens = match exchange_downstream_code(&app, ds, downstream_code, &name).await {
        Ok(t) => t,
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

async fn exchange_downstream_code(
    app: &AppState,
    ds: &crate::config::DownstreamConfig,
    code: &str,
    name: &str,
) -> Result<DownstreamTokens, String> {
    let callback_url = format!("{}/callback/mcp/{}", app.config.server.public_url, name);

    let body = chained_oauth::post_downstream_token(
        &app.http_client,
        ds,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", ds.oauth_client_id.as_str()),
            ("client_secret", ds.oauth_client_secret.as_str()),
            ("code", code),
            ("redirect_uri", callback_url.as_str()),
        ],
    )
    .await?;

    let access_token = body["access_token"]
        .as_str()
        .ok_or("Missing access_token in downstream response")?
        .to_string();

    let refresh_token = body["refresh_token"].as_str().map(String::from);
    let expires_in = body["expires_in"].as_u64();

    Ok(DownstreamTokens::ChainedOAuth {
        access_token,
        refresh_token,
        expires_in,
    })
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
