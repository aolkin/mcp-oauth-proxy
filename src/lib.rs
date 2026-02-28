mod auth;
pub mod config;
pub mod oauth;
pub mod proxy;
pub mod routes;

use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::Config>,
    pub state_secret: Vec<u8>,
    pub http_client: reqwest::Client,
}

impl AppState {
    pub fn find_downstream(&self, name: &str) -> Option<&config::DownstreamConfig> {
        self.config.downstreams.iter().find(|ds| ds.name == name)
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
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
        .with_state(state)
}
