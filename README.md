# mcp-oauth-proxy

> This repository has been archived in favor of Cloudflare MCP Server Portal, which accomplishes the same goal.

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

## Quick Start

```bash
# Clone and build
cargo build --release

# Edit config
cp config.example.toml config.toml
# (configure your downstream MCPs — see docs/CONFIG.md)

# Generate a secret key
openssl rand -base64 32
# Put this value in config.toml as state_secret

# Run
./target/release/mcp-oauth-proxy --config config.toml

# In Claude's connector settings, add your MCP URL:
#   https://your-domain.com/mcp/github
# Claude will discover OAuth endpoints automatically via .well-known
```

## Setup Walkthrough: From Zero to Working Proxy

### 1. Build

```bash
cargo build --release
```

Or with Docker:

```bash
docker build -t mcp-oauth-proxy .
```

### 2. Configure

```bash
cp config.example.toml config.toml
```

Edit `config.toml`:
- Set `public_url` to your HTTPS domain (e.g., `https://mcp.example.com`)
- Generate a secret: `openssl rand -base64 32` and set `state_secret`
- Add one or more `[[downstream]]` entries (see [docs/CONFIG.md](./docs/CONFIG.md))

For chained OAuth (e.g., GitHub):
- Register an OAuth App at the provider (e.g., https://github.com/settings/developers)
- Set the callback URL to `https://your-domain.com/callback/mcp/<name>`
- Put `oauth_client_id` and `oauth_client_secret` in config (or use env vars)

### 3. Deploy with HTTPS

Claude's connectors require HTTPS. Choose one of:

**Option A: Behind Caddy (automatic TLS)**
```
# Caddyfile
mcp.example.com {
    reverse_proxy localhost:8080
}
```

**Option B: Behind nginx**
```nginx
server {
    listen 443 ssl;
    server_name mcp.example.com;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;  # Important for SSE
    }
}
```

**Option C: Cloudflare Tunnel (easiest)**
```bash
cloudflared tunnel --url http://localhost:8080
```

**Option D: Docker**
```bash
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/config.toml:/etc/mcp-oauth-proxy/config.toml:ro \
  -e MCP_PROXY_STATE_SECRET="$(openssl rand -base64 32)" \
  mcp-oauth-proxy
```

### 4. Connect from Claude

In Claude's connector settings, add your MCP URL:
```
https://mcp.example.com/mcp/github
```

Claude will automatically:
1. Discover OAuth endpoints via `GET /.well-known/oauth-protected-resource/mcp/github`
2. Redirect you to authorize (form for passthrough, or OAuth provider for chained)
3. Exchange the authorization code for tokens
4. Start making MCP requests through the proxy

### 5. Health Check

Verify the proxy is running:
```bash
curl https://mcp.example.com/health
# Returns: OK
```

## Logging

Control log level with `RUST_LOG`:

```bash
RUST_LOG=info ./target/release/mcp-oauth-proxy --config config.toml
RUST_LOG=debug ./target/release/mcp-oauth-proxy --config config.toml
```

Logged events: request method + path, response status, downstream URL (on proxy), auth flow events (authorize, code issued, code exchanged, refresh proxied).

Never logged: access tokens, refresh tokens, API keys, PKCE verifiers, state blobs.

## Environment Variables

| Variable | Overrides |
|----------|-----------|
| `RUST_LOG` | Log level (default: `info`) |
| `MCP_PROXY_STATE_SECRET` | `server.state_secret` |
| `MCP_PROXY_<NAME>_CLIENT_SECRET` | `downstream[name].oauth_client_secret` |

## Documentation

- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) — Auth flows, component design, SSE proxying
- [docs/API-SPEC.md](./docs/API-SPEC.md) — All HTTP endpoints with request/response formats
- [docs/CONFIG.md](./docs/CONFIG.md) — Configuration file reference
- [docs/DEVELOPMENT.md](./docs/DEVELOPMENT.md) — Development guide and testing
