# Configuration Reference

The proxy is configured via a TOML file specifying global settings and downstream MCP definitions.

## Example Config

```toml
[server]
# Address to bind to
host = "0.0.0.0"
port = 8080

# Public-facing base URL (used to generate .well-known URLs and redirect URIs)
# Must be HTTPS in production
public_url = "https://mcp-proxy.example.com"

# Secret key for HMAC-signing state parameters (chained OAuth) and
# AES-256-GCM encrypting authorization codes (stateless auth codes).
# Generate with: openssl rand -base64 32
# Can also be set via MCP_PROXY_STATE_SECRET env var (env var takes precedence)
state_secret = "CHANGE_ME_TO_A_RANDOM_32_BYTE_BASE64_STRING"

# Authorization code TTL in seconds (default: 300 = 5 minutes)
# The expiry is embedded inside the encrypted auth code — no server-side storage needed.
auth_code_ttl = 300

# ─────────────────────────────────────────────
# Downstream MCP definitions
# ─────────────────────────────────────────────

# ── Passthrough example: Linear ──
[[downstream]]
# URL path identifier (becomes /mcp/linear, /authorize/mcp/linear, etc.)
name = "linear"

# Human-readable label shown on the authorize form
display_name = "Linear"

# Auth strategy: "passthrough" or "chained_oauth"
strategy = "passthrough"

# Downstream MCP server URL
downstream_url = "https://mcp.linear.app/sse"

# How to format the bearer token for downstream requests
# Options:
#   "Bearer"      → Authorization: Bearer <token>  (default)
#   "token"       → Authorization: token <token>
#   "Basic"       → Authorization: Basic <token>
#   "X-API-Key"   → X-API-Key: <token>
#   "X-Whatever"  → X-Whatever: <token>
auth_header_format = "Bearer"

# Optional: hint text shown on the authorize form
auth_hint = "Paste your Linear API key. You can generate one at Settings → API → Personal API Keys."

# Optional: scopes to advertise in .well-known metadata
scopes = ""

# ── Passthrough example: custom MCP with non-standard header ──
[[downstream]]
name = "internal-tool"
display_name = "Internal Tool MCP"
strategy = "passthrough"
downstream_url = "https://internal.corp.com/mcp"
auth_header_format = "X-API-Key"
auth_hint = "Enter your Internal Tool API key."

# ── Chained OAuth example: GitHub ──
[[downstream]]
name = "github"
display_name = "GitHub"
strategy = "chained_oauth"

# The actual MCP server to proxy to after auth
downstream_url = "https://api.githubcopilot.com/mcp/"

# How to format the token for the downstream MCP server
# GitHub MCP expects standard Bearer tokens
auth_header_format = "Bearer"

# ── Chained OAuth provider config ──

# Downstream OAuth endpoints
oauth_authorize_url = "https://github.com/login/oauth/authorize"
oauth_token_url = "https://github.com/login/oauth/access_token"

# Your registered OAuth App credentials
# client_secret can also be set via env var: MCP_PROXY_GITHUB_CLIENT_SECRET
oauth_client_id = "Iv1.your_github_client_id"
oauth_client_secret = "your_github_client_secret_here"

# Scopes to request from the downstream provider
oauth_scopes = "repo read:org"

# Whether the downstream provider issues refresh tokens
# If true, refresh_token grant type is advertised and proxied
oauth_supports_refresh = true

# The downstream provider's expected Accept header for token exchange
# GitHub specifically requires this
oauth_token_accept = "application/json"
```

## Field Reference

### `[server]`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `host` | string | No | `"0.0.0.0"` | Bind address |
| `port` | integer | No | `8080` | Bind port |
| `public_url` | string | **Yes** | — | Public HTTPS URL of the proxy. Used in all generated URLs. No trailing slash. |
| `state_secret` | string | **Yes** | — | Secret key for HMAC state signing and AES-256-GCM auth code encryption. Override with `MCP_PROXY_STATE_SECRET` env var. |
| `auth_code_ttl` | integer | No | `300` | Authorization code lifetime in seconds (embedded in encrypted code) |

### `[[downstream]]` — Common Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | **Yes** | — | URL path segment. Alphanumeric + hyphens only. Must be unique. |
| `display_name` | string | **Yes** | — | Human-readable name shown in UI |
| `strategy` | string | **Yes** | — | `"passthrough"` or `"chained_oauth"` |
| `downstream_url` | string | **Yes** | — | The actual MCP server URL to proxy to |
| `auth_header_format` | string | No | `"Bearer"` | How to format the downstream auth header |
| `scopes` | string | No | `""` | Scopes to advertise in `.well-known` metadata |

### `[[downstream]]` — Passthrough-Only Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `auth_hint` | string | No | `""` | Help text shown on the authorization form |

### `[[downstream]]` — Chained OAuth Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `oauth_authorize_url` | string | **Yes** | — | Downstream provider's authorization endpoint |
| `oauth_token_url` | string | **Yes** | — | Downstream provider's token endpoint |
| `oauth_client_id` | string | **Yes** | — | Your registered client ID with the provider |
| `oauth_client_secret` | string | **Yes** | — | Your registered client secret. Override with `MCP_PROXY_<NAME>_CLIENT_SECRET` env var (name uppercased, hyphens→underscores) |
| `oauth_scopes` | string | No | `""` | Scopes to request from downstream provider |
| `oauth_supports_refresh` | bool | No | `false` | Whether to advertise and proxy refresh tokens |
| `oauth_token_accept` | string | No | `"application/json"` | Accept header value for downstream token exchange |

## Environment Variable Overrides

Sensitive values can be provided via environment variables instead of the config file. Env vars take precedence.

| Env Var | Overrides |
|---------|-----------|
| `MCP_PROXY_STATE_SECRET` | `server.state_secret` |
| `MCP_PROXY_<NAME>_CLIENT_SECRET` | `downstream[name].oauth_client_secret` |

`<NAME>` is the downstream `name` field, uppercased, with hyphens replaced by underscores. E.g., for `name = "github"`, the env var is `MCP_PROXY_GITHUB_CLIENT_SECRET`.

## Validation Rules

On startup, the proxy should validate:

1. `public_url` starts with `https://` (warn if `http://`, allow for local dev)
2. All downstream `name` values are unique
3. All downstream `name` values match `^[a-z0-9-]+$`
4. Chained OAuth downstreams have all required `oauth_*` fields
5. `state_secret` is at least 32 bytes when decoded from base64
6. `downstream_url` is a valid URL
7. `auth_header_format` is a recognized value

Exit with a clear error message on validation failure.
