mod auth;
mod config;
mod oauth;
mod proxy;
mod routes;

use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use std::path::PathBuf;

/// MCP OAuth Proxy — bridges OAuth 2.1 for Claude's MCP connectors
/// to downstream MCP servers using various auth strategies.
#[derive(Parser, Debug)]
#[command(name = "mcp-oauth-proxy", version, about)]
struct Cli {
    /// Path to the TOML configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Port to listen on (overrides config file)
    #[arg(short, long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let mut cfg = match config::load_config(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Configuration error: {e}");
            std::process::exit(1);
        }
    };

    // CLI --port overrides config
    if let Some(port) = cli.port {
        cfg.server.port = port;
    }

    tracing::info!(
        downstreams = cfg.downstreams.len(),
        "Configuration loaded successfully"
    );
    for ds in &cfg.downstreams {
        tracing::info!(
            name = %ds.name,
            strategy = ?ds.strategy,
            downstream_url = %ds.downstream_url,
            "  Downstream configured"
        );
    }

    let app = Router::new()
        // Discovery endpoints
        .route(
            "/.well-known/oauth-protected-resource/mcp/:name",
            get(routes::well_known::protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server/mcp/:name",
            get(routes::well_known::authorization_server),
        )
        // Authorization endpoints
        .route(
            "/authorize/mcp/:name",
            get(routes::authorize::authorize_get).post(routes::authorize::authorize_post),
        )
        .route("/callback/mcp/:name", get(routes::authorize::callback))
        // Token endpoint
        .route("/token/mcp/:name", post(routes::token::token))
        // MCP proxy endpoints
        .route(
            "/mcp/:name",
            get(routes::mcp_proxy::mcp_sse).post(routes::mcp_proxy::mcp_post),
        );

    let bind_addr = format!("{}:{}", cfg.server.host, cfg.server.port);
    tracing::info!("Listening on {bind_addr}");
    tracing::info!("Public URL: {}", cfg.server.public_url);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to bind to {bind_addr}: {e}");
            std::process::exit(1);
        });

    axum::serve(listener, app).await.unwrap_or_else(|e| {
        tracing::error!("Server error: {e}");
        std::process::exit(1);
    });
}
