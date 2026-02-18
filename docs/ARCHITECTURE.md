# Architecture

## Overview

The proxy is a single Rust binary that serves multiple downstream MCP connections on different URL paths under one domain. Claude discovers each connection's OAuth configuration independently via path-based `.well-known` endpoints.

```
Claude ──OAuth 2.1──► mcp-oauth-proxy ──any auth──► Downstream MCP Server
                      (your-domain.com)

Claude sees:
  https://your-domain.com/mcp/github     → GitHub MCP (chained OAuth)
  https://your-domain.com/mcp/linear     → Linear MCP (passthrough API key)
  https://your-domain.com/mcp/custom     → Custom MCP (passthrough bearer token)
```

## Path-Based Routing

Every downstream MCP is identified by a path prefix. All endpoints use this prefix to determine which downstream config to use.

For a downstream registered as `github` at path `/mcp/github`:

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/oauth-protected-resource/mcp/github` | Protected resource metadata (points to auth server) |
| `GET /.well-known/oauth-authorization-server/mcp/github` | OAuth server metadata (endpoint URLs) |
| `GET /authorize/mcp/github` | Authorization page (form or redirect) |
| `POST /token/mcp/github` | Token exchange and refresh |
| `GET /mcp/github` | MCP SSE endpoint (proxied) |
| `POST /mcp/github` | MCP HTTP endpoint (proxied) |

## Authentication Flows

### Flow 1: Passthrough (API Key / Bearer Token)

Best for downstream MCPs that accept a static token.

```
┌───────┐         ┌───────────┐         ┌──────────────┐
│ Claude │         │   Proxy   │         │ Downstream   │
└───┬───┘         └─────┬─────┘         └──────┬───────┘
    │                   │                      │
    │ 1. GET /.well-known/oauth-protected-resource/mcp/linear
    │──────────────────►│                      │
    │◄──────────────────│ { resource, auth_server_url }
    │                   │                      │
    │ 2. GET /.well-known/oauth-authorization-server/mcp/linear
    │──────────────────►│                      │
    │◄──────────────────│ { authorize, token endpoints }
    │                   │                      │
    │ 3. Redirect user to /authorize/mcp/linear?
    │    response_type=code&code_challenge=...&
    │    redirect_uri=...&state=...
    │──────────────────►│                      │
    │                   │                      │
    │   4. Proxy serves HTML form:             │
    │      "Paste your Linear API key"         │
    │                   │                      │
    │   5. User submits form with API key      │
    │                   │                      │
    │   6. Proxy generates encrypted auth code  │
    │      containing { api_key, pkce_challenge,│
    │      redirect_uri, expiry } — stateless  │
    │                   │                      │
    │   7. Redirect to redirect_uri?code=...&state=...
    │◄──────────────────│                      │
    │                   │                      │
    │ 8. POST /token/mcp/linear               │
    │    grant_type=authorization_code         │
    │    code=...&code_verifier=...            │
    │──────────────────►│                      │
    │                   │                      │
    │   9. Proxy decrypts code, verifies PKCE,  │
    │      returns the API key AS the          │
    │      access_token. No refresh token.     │
    │                   │                      │
    │◄──────────────────│ { access_token: "<the api key>" }
    │                   │                      │
    │ 10. GET /mcp/linear                      │
    │     Authorization: Bearer <the api key>  │
    │──────────────────►│                      │
    │                   │ 11. Proxy reformats  │
    │                   │     header and       │
    │                   │     proxies request  │
    │                   │────────────────────►│
    │                   │◄────────────────────│
    │◄──────────────────│ (SSE stream)         │
```

**Key points:**
- The authorization code is a short-lived (5 minutes) AES-256-GCM encrypted blob containing the downstream token, PKCE challenge, redirect URI, and expiry. No server-side storage is needed — the code is fully self-contained.
- The downstream API key is returned directly as the access token — no persistent storage needed.
- The proxy reformats the auth header based on config (e.g., `Authorization: Bearer X` → `X-API-Key: X`, or `Authorization: token X`).

### Flow 2: Chained OAuth (e.g., GitHub)

Best for downstream services that have their own OAuth flow.

```
┌───────┐         ┌───────────┐      ┌──────────┐     ┌──────────────┐
│ Claude │         │   Proxy   │      │  GitHub  │     │ GitHub MCP   │
└───┬───┘         └─────┬─────┘      │  OAuth   │     └──────┬───────┘
    │                   │             └────┬─────┘            │
    │ 1-3. Same discovery + authorize redirect as above       │
    │──────────────────►│                  │                   │
    │                   │                  │                   │
    │   4. Proxy redirects user to         │                   │
    │      GitHub's authorize URL          │                   │
    │      (with proxy's GitHub client_id, │                   │
    │       requested scopes, and a state  │                   │
    │       that encodes the original      │                   │
    │       PKCE challenge + Claude's      │                   │
    │       redirect_uri + Claude's state) │                   │
    │                   │─────────────────►│                   │
    │                   │                  │                   │
    │   5. User authorizes on GitHub       │                   │
    │                   │                  │                   │
    │   6. GitHub redirects back to proxy  │                   │
    │      callback with GitHub auth code  │                   │
    │                   │◄─────────────────│                   │
    │                   │                  │                   │
    │   7. Proxy exchanges GitHub code     │                   │
    │      for GitHub access + refresh     │                   │
    │      tokens                          │                   │
    │                   │─────────────────►│                   │
    │                   │◄─────────────────│                   │
    │                   │                  │                   │
    │   8. Proxy generates encrypted auth   │                   │
    │      code containing:                │                   │
    │      { gh_access_token,              │                   │
    │        gh_refresh_token,             │                   │
    │        pkce_challenge, expiry }      │                   │
    │                   │                  │                   │
    │   9. Redirect to Claude's            │                   │
    │      redirect_uri with proxy's code  │                   │
    │◄──────────────────│                  │                   │
    │                   │                  │                   │
    │ 10. POST /token/mcp/github           │                   │
    │     grant_type=authorization_code    │                   │
    │──────────────────►│                  │                   │
    │                   │                  │                   │
    │   11. Proxy verifies PKCE, returns   │                   │
    │       GitHub tokens as proxy tokens: │                   │
    │       access_token = gh_access_token │                   │
    │       refresh_token = gh_refresh     │                   │
    │◄──────────────────│                  │                   │
    │                   │                  │                   │
    │ 12. GET /mcp/github                  │                   │
    │     Authorization: Bearer <gh_token> │                   │
    │──────────────────►│                  │                   │
    │                   │ 13. Proxy passes │                   │
    │                   │     token through│                   │
    │                   │─────────────────────────────────────►│
    │                   │◄─────────────────────────────────────│
    │◄──────────────────│ (SSE stream)     │                   │
    │                   │                  │                   │
    │ == Later, token expires ==           │                   │
    │                   │                  │                   │
    │ 14. POST /token/mcp/github           │                   │
    │     grant_type=refresh_token         │                   │
    │     refresh_token=<gh_refresh>       │                   │
    │──────────────────►│                  │                   │
    │                   │ 15. Proxy calls  │                   │
    │                   │     GitHub's     │                   │
    │                   │     /token with  │                   │
    │                   │     refresh      │                   │
    │                   │─────────────────►│                   │
    │                   │◄─────────────────│ new tokens        │
    │                   │                  │                   │
    │◄──────────────────│ { new access, new refresh }          │
```

**Key points:**
- You need a registered GitHub OAuth App (or GitHub App) with your proxy's callback URL.
- The proxy's `state` parameter to GitHub encodes everything needed to complete the flow back to Claude (Claude's state, redirect_uri, PKCE challenge). Sign or encrypt this blob to prevent tampering.
- GitHub's tokens are passed through directly — the proxy is fully stateless after the code exchange.
- Refresh is a pure passthrough: Claude sends the GitHub refresh token, proxy forwards to GitHub, returns new tokens.
- **Risk**: GitHub uses rotating, single-use refresh tokens. A failed refresh means the user must re-authorize. This is an acceptable tradeoff for statelessness.

## Component Design

### Stateless Encrypted Authorization Codes

**Fully stateless.** Authorization codes are AES-256-GCM encrypted blobs — no in-memory HashMap, no sweeper task, no concerns about multi-instance deployments.

The authorization code itself contains everything needed for token exchange:

```
auth_code = base64url( nonce || AES-256-GCM( plaintext, key, nonce ) )
```

The plaintext is JSON:
```json
{
    "downstream_tokens": { "type": "passthrough", "access_token": "..." },
    "pkce_challenge": "...",
    "redirect_uri": "...",
    "exp": 1234567890
}
```

The AES-256 key is derived by SHA-256 hashing the server's `state_secret` (the same secret used for HMAC state signing in chained OAuth). A fresh random 12-byte nonce is generated per code.

```rust
enum DownstreamTokens {
    Passthrough {
        access_token: String,     // The raw API key / token
    },
    ChainedOAuth {
        access_token: String,     // Downstream access token
        refresh_token: Option<String>,  // Downstream refresh token
        expires_in: Option<u64>,  // Downstream token TTL
    },
}
```

On `/token`, the proxy:
1. Base64url-decodes the authorization code
2. Splits off the 12-byte nonce
3. Decrypts with AES-256-GCM (authentication tag prevents tampering)
4. Checks the embedded `exp` timestamp
5. Verifies PKCE and redirect_uri match
6. Returns the embedded downstream tokens

**Benefits over in-memory store:**
- No shared state — works with multiple proxy instances behind a load balancer
- No background sweeper task needed — expiry is checked on decryption
- No memory growth from abandoned auth flows
- Authorization codes are tamper-proof via AES-GCM authentication tag

### SSE Proxy

The MCP protocol uses SSE (Server-Sent Events) for server→client streaming. The proxy must:

1. Accept Claude's SSE connection on `GET /mcp/<path>`
2. Open a corresponding SSE connection (or HTTP request) to the downstream MCP server
3. Stream events from downstream back to Claude, unmodified
4. Handle Claude's POST requests to `/mcp/<path>` for client→server messages (JSON-RPC over HTTP)

Use `reqwest`'s streaming response + `axum`'s SSE support (`axum::response::sse::Sse`). The proxy reads chunks from the downstream response and forwards them as SSE events.

```rust
// Pseudocode for SSE proxy
async fn proxy_sse(
    bearer_token: String,
    downstream_url: &str,
    header_mapping: &HeaderMapping,
) -> Sse<impl Stream<Item = Result<Event, Error>>> {
    let downstream_resp = reqwest::Client::new()
        .get(downstream_url)
        .header(header_mapping.format(bearer_token))
        .send()
        .await?;

    let stream = downstream_resp
        .bytes_stream()
        .map(|chunk| parse_sse_events(chunk))
        .flat_map(stream::iter);

    Sse::new(stream)
}
```

### Header Remapping

Each downstream config specifies how to translate the bearer token into the downstream auth header:

| Config `auth_header_format` | Bearer token `abc123` becomes |
|---|---|
| `Bearer` (default) | `Authorization: Bearer abc123` |
| `token` | `Authorization: token abc123` |
| `Basic` | `Authorization: Basic abc123` |
| `X-API-Key` | `X-API-Key: abc123` |
| `Custom-Header` | `Custom-Header: abc123` |

Anything that starts with `X-` or other non-standard prefixes gets sent as a standalone header. Standard `Authorization` scheme values get prefixed appropriately.

### State Signing (Chained OAuth)

For chained OAuth, the proxy encodes Claude's original request parameters into the `state` parameter sent to the downstream OAuth provider. This state must be tamper-proof.

Use HMAC-SHA256 with a server secret (from config or env var):

```
state = base64url(json_payload) + "." + base64url(hmac_sha256(json_payload, secret))
```

The JSON payload contains:
```json
{
  "claude_state": "<Claude's original state param>",
  "claude_redirect_uri": "<Claude's redirect URI>",
  "pkce_challenge": "<Claude's PKCE code_challenge>",
  "pkce_method": "S256",
  "exp": 1234567890
}
```

On callback from the downstream provider, verify the HMAC before proceeding.

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Invalid/expired auth code | Return `400` with `{"error": "invalid_grant"}` |
| PKCE verification failure | Return `400` with `{"error": "invalid_grant"}` |
| Invalid bearer token on MCP request | Return `401` (Claude should re-authorize) |
| Downstream MCP unreachable | Return `502` with descriptive error |
| Downstream refresh fails | Return `400` with `{"error": "invalid_grant"}` — Claude should re-authorize |
| Unknown path prefix | Return `404` |

All error responses from `/token` must be JSON per RFC 6749 §5.2.

## Security Considerations

1. **HTTPS required.** The proxy must be behind TLS. Tokens travel in headers.
2. **PKCE is mandatory.** Never skip PKCE verification — it prevents authorization code interception.
3. **State signing.** For chained OAuth, always verify the HMAC on the state parameter to prevent CSRF and parameter injection.
4. **Auth code encryption.** Authorization codes are AES-256-GCM encrypted with a random nonce per code. The authentication tag prevents tampering, and the key is derived from the `state_secret`.
5. **No logging of tokens.** Never log access tokens, refresh tokens, or API keys. Log request paths and status codes only.
6. **CORS.** The authorize page needs to work in a browser redirect flow. MCP endpoints may need appropriate CORS headers depending on how Claude's connector initiates requests.
7. **Rate limiting.** Consider rate limiting `/token` and `/authorize` to prevent brute force. Even a simple in-memory counter per IP is better than nothing.
