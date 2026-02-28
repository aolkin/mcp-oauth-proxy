pub mod config;
pub mod proxy;
pub mod routes;

mod auth;
mod oauth;

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
