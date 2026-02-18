# mcp-oauth-proxy

A lightweight Rust proxy that sits between Claude's MCP connector (which requires OAuth 2.1) and downstream MCP servers that use other authentication methods. It presents a compliant OAuth 2.1 interface to Claude while handling credential translation to downstream services.

## What This Solves

Claude's web interface supports MCP (Model Context Protocol) servers via "connectors," but only supports OAuth-based authentication. Many MCP servers use simpler auth (API keys, bearer tokens). This proxy bridges that gap.

## Supported Auth Strategies

### 1. Passthrough
The user provides a token/API key during the OAuth authorize flow. The proxy returns it directly as the OAuth access token to Claude. On each MCP request, the proxy forwards it to the downstream server, optionally reformatting the header.

**No storage required.** Best for long-lived API keys or personal access tokens.

### 2. Chained OAuth
The proxy initiates a real OAuth flow with the downstream service (e.g., GitHub). The downstream service's tokens are passed through to Claude as the proxy's tokens. Claude handles refresh transparently — the proxy just forwards refresh requests to the downstream token endpoint.

**No storage required** (stateless). Tradeoff: if a rotating refresh token is lost mid-refresh, the user must re-authorize.

## Tech Stack

- **Rust** with `axum` for HTTP/SSE
- **reqwest** for outbound HTTP to downstream MCPs
- **TOML** config file for downstream MCP definitions
- Deployable anywhere: OCI free tier, a VPS, Docker, etc.

## Project Structure

```
mcp-oauth-proxy/
├── Cargo.toml
├── config.toml              # Downstream MCP definitions
├── src/
│   ├── main.rs              # Entrypoint, router setup
│   ├── config.rs            # Config parsing
│   ├── routes/
│   │   ├── mod.rs
│   │   ├── well_known.rs    # /.well-known/oauth-authorization-server/*
│   │   ├── authorize.rs     # /authorize/* (HTML form + submission)
│   │   ├── token.rs         # /token/* (code exchange + refresh)
│   │   └── mcp_proxy.rs     # /mcp/* (SSE proxy to downstream)
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── passthrough.rs   # Passthrough strategy logic
│   │   └── chained_oauth.rs # Chained OAuth strategy logic
│   ├── oauth/
│   │   ├── mod.rs
│   │   ├── pkce.rs          # PKCE verification
│   │   └── codes.rs         # Stateless encrypted authorization codes (AES-256-GCM)
│   └── proxy/
│       ├── mod.rs
│       └── sse.rs           # SSE stream proxying
```

## Quick Start

```bash
# Clone and build
cargo build --release

# Edit config
cp config.example.toml config.toml
# (configure your downstream MCPs - see CONFIG.md)

# Run
./target/release/mcp-oauth-proxy --config config.toml --port 8080

# In Claude's connector settings, add your MCP URL:
#   https://your-domain.com/mcp/github
# Claude will discover OAuth endpoints via:
#   GET /.well-known/oauth-protected-resource/mcp/github
#   GET /.well-known/oauth-authorization-server/mcp/github
```

## Deployment

### Requirements
- A domain with HTTPS (Claude's connector requires it)
- Rust 1.75+ to build
- A reverse proxy (nginx/caddy) for TLS termination, or run behind Cloudflare Tunnel

### Docker
```dockerfile
FROM rust:1.75 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/mcp-oauth-proxy /usr/local/bin/
COPY config.toml /etc/mcp-oauth-proxy/config.toml
EXPOSE 8080
CMD ["mcp-oauth-proxy", "--config", "/etc/mcp-oauth-proxy/config.toml"]
```

## Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) — Detailed auth flows, component design, SSE proxying
- [API_SPEC.md](./API_SPEC.md) — All HTTP endpoints with request/response formats
- [CONFIG.md](./CONFIG.md) — Configuration file reference with examples
