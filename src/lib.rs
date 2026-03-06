mod auth;
pub mod config;
pub mod oauth;
pub mod proxy;
pub mod routes;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::Config>,
    pub state_secret: Vec<u8>,
    pub http_client: reqwest::Client,
}

impl AppState {
    pub fn new(
        config: config::Config,
        state_secret: Vec<u8>,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            config: Arc::new(config),
            state_secret,
            http_client,
        }
    }

    pub fn find_downstream(&self, name: &str) -> Option<&config::DownstreamConfig> {
        self.config.downstream.get(name)
    }
}

async fn health() -> &'static str {
    "OK"
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/oauth-protected-resource/mcp/{name}",
            get(routes::well_known::protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server/mcp/{name}",
            get(routes::well_known::authorization_server),
        )
        .route(
            "/authorize/mcp/{name}",
            get(routes::authorize::authorize_get).post(routes::authorize::authorize_post),
        )
        .route("/callback/mcp/{name}", get(routes::authorize::callback))
        .route("/token/mcp/{name}", post(routes::token::token))
        .route(
            "/mcp/{name}",
            get(routes::mcp_proxy::mcp_sse).post(routes::mcp_proxy::mcp_post),
        )
        .layer(DefaultBodyLimit::max(10 * 1_048_576))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
