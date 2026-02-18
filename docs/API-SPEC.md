# API Specification

All endpoints use `<path_prefix>` to identify the downstream MCP. For example, if a downstream is configured with path `github`, the prefix is `/mcp/github`.

## Discovery Endpoints

### GET `/.well-known/oauth-protected-resource/<path_prefix>`

Returns metadata about the protected resource per RFC 9728. Claude calls this first.

**Response: `200 OK`**
```json
{
  "resource": "https://your-domain.com/mcp/github",
  "authorization_servers": [
    "https://your-domain.com/mcp/github"
  ]
}
```

The `resource` value is the MCP endpoint URL. The `authorization_servers` value tells Claude where to find the OAuth server metadata.

### GET `/.well-known/oauth-authorization-server/<path_prefix>`

Returns OAuth 2.1 authorization server metadata per RFC 8414.

**Response: `200 OK`**
```json
{
  "issuer": "https://your-domain.com/mcp/github",
  "authorization_endpoint": "https://your-domain.com/authorize/mcp/github",
  "token_endpoint": "https://your-domain.com/token/mcp/github",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"]
}

```

**Notes:**
- For passthrough-type downstreams, omit `"refresh_token"` from `grant_types_supported`.
- `token_endpoint_auth_methods_supported` is `["none"]` because Claude is a public client (no client secret).

## Authorization Endpoint

### GET `/authorize/<path_prefix>`

Claude redirects the user's browser here. This endpoint serves different experiences depending on the auth strategy.

**Query parameters (from Claude):**

| Param | Required | Description |
|-------|----------|-------------|
| `response_type` | Yes | Must be `code` |
| `client_id` | Yes | Claude's client ID (accept any value) |
| `redirect_uri` | Yes | Where to send the user back to Claude |
| `state` | Yes | Opaque string, must be returned unchanged |
| `code_challenge` | Yes | PKCE S256 challenge |
| `code_challenge_method` | Yes | Must be `S256` |
| `scope` | No | Requested scopes (may be empty) |

#### Strategy: Passthrough

**Serves an HTML page** with a form asking the user to paste their API key/token.

The form should:
- Clearly name the downstream service (from config)
- Have a password-type input field for the token
- Optionally show what scopes/permissions are needed (from config)
- Submit via POST to the same URL

**On form submission (POST):**

1. Create an encrypted authorization code via AES-256-GCM containing `{ token, pkce_challenge, redirect_uri, exp: now + auth_code_ttl }` (see ARCHITECTURE.md § Stateless Encrypted Authorization Codes)
2. Redirect to `redirect_uri?code=<encrypted_code>&state=<state>`

#### Strategy: Chained OAuth

**Redirects the user** to the downstream OAuth provider's authorize URL.

1. Build the state blob for the downstream provider:
   ```json
   {
     "claude_state": "<state from Claude>",
     "claude_redirect_uri": "<redirect_uri from Claude>",
     "pkce_challenge": "<code_challenge from Claude>",
     "pkce_method": "S256",
     "exp": <unix_timestamp + 600>
   }
   ```
2. HMAC-sign the blob (see ARCHITECTURE.md § State Signing)
3. Redirect to downstream authorize URL:
   ```
   https://github.com/login/oauth/authorize?
     client_id=<your_github_app_client_id>&
     redirect_uri=https://your-domain.com/callback/mcp/github&
     state=<signed_blob>&
     scope=<scopes_from_config>
   ```

### GET `/callback/<path_prefix>`

**Only used for chained OAuth.** The downstream OAuth provider redirects back here.

**Query parameters (from downstream provider):**

| Param | Description |
|-------|-------------|
| `code` | Authorization code from downstream |
| `state` | The signed blob from step above |

**Processing:**

1. Verify HMAC on state, check expiration
2. Extract Claude's original parameters from state
3. Exchange downstream code for tokens:
   ```
   POST https://github.com/login/oauth/access_token
   Content-Type: application/json
   Accept: application/json

   {
     "client_id": "<your_github_client_id>",
     "client_secret": "<your_github_client_secret>",
     "code": "<downstream_code>",
     "redirect_uri": "https://your-domain.com/callback/mcp/github"
   }
   ```
4. Create an encrypted proxy authorization code via AES-256-GCM containing `{ downstream_tokens, pkce_challenge, redirect_uri, exp }` (see ARCHITECTURE.md § Stateless Encrypted Authorization Codes)
5. Redirect to Claude's redirect_uri: `<claude_redirect_uri>?code=<encrypted_proxy_code>&state=<claude_state>`

## Token Endpoint

### POST `/token/<path_prefix>`

Handles both authorization code exchange and refresh token grants.

**Content-Type:** `application/x-www-form-urlencoded`

**Response Content-Type:** `application/json`

#### Grant Type: `authorization_code`

**Request body:**

| Param | Required | Description |
|-------|----------|-------------|
| `grant_type` | Yes | `authorization_code` |
| `code` | Yes | The authorization code |
| `code_verifier` | Yes | PKCE verifier (plaintext, will be S256-hashed and compared to stored challenge) |
| `redirect_uri` | Yes | Must match the one used in `/authorize` |
| `client_id` | Yes | Claude's client ID (accept any value) |

**Processing:**

1. Decrypt the authorization code using AES-256-GCM with the server's `state_secret`
2. Verify the code hasn't expired (check embedded `exp` timestamp)
3. Verify `redirect_uri` matches the value embedded in the code
4. Verify PKCE: `base64url(sha256(code_verifier)) == embedded_challenge`
5. Return the embedded downstream tokens

**Success response: `200 OK`**

For passthrough:
```json
{
  "access_token": "<the downstream api key>",
  "token_type": "Bearer"
}
```

For chained OAuth:
```json
{
  "access_token": "<downstream_access_token>",
  "token_type": "Bearer",
  "expires_in": 28800,
  "refresh_token": "<downstream_refresh_token>"
}
```

**Error response: `400 Bad Request`**
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code expired or invalid"
}
```

#### Grant Type: `refresh_token`

**Only supported for chained OAuth downstreams.**

**Request body:**

| Param | Required | Description |
|-------|----------|-------------|
| `grant_type` | Yes | `refresh_token` |
| `refresh_token` | Yes | The refresh token to use |
| `client_id` | Yes | Claude's client ID (accept any value) |

**Processing:**

1. Look up downstream config for this path prefix
2. Forward refresh request to downstream token endpoint:
   ```
   POST <downstream_token_url>
   Content-Type: application/x-www-form-urlencoded

   grant_type=refresh_token&
   refresh_token=<the_refresh_token>&
   client_id=<your_downstream_client_id>&
   client_secret=<your_downstream_client_secret>
   ```
3. Return downstream's response, mapping fields as needed

**Success response: `200 OK`**
```json
{
  "access_token": "<new_downstream_access_token>",
  "token_type": "Bearer",
  "expires_in": 28800,
  "refresh_token": "<new_downstream_refresh_token>"
}
```

**Error response:** Forward downstream's error, or return:
```json
{
  "error": "invalid_grant",
  "error_description": "Refresh token invalid or expired. User must re-authorize."
}
```

## MCP Proxy Endpoints

### GET `/mcp/<path_prefix>`

SSE endpoint. Claude connects here for server→client streaming.

**Request headers:**
```
Authorization: Bearer <access_token>
Accept: text/event-stream
```

**Processing:**

1. Extract bearer token from `Authorization` header
2. Look up downstream config for path prefix
3. Reformat auth header per config (see ARCHITECTURE.md § Header Remapping)
4. Open SSE connection to downstream MCP server URL
5. Stream all SSE events from downstream back to Claude, unmodified
6. If downstream returns non-200, return appropriate error to Claude

**Response:** SSE stream (`Content-Type: text/event-stream`)

**Error responses:**
- `401 Unauthorized` — missing or malformed bearer token
- `502 Bad Gateway` — downstream MCP server unreachable or returned an error

### POST `/mcp/<path_prefix>`

HTTP endpoint for client→server MCP messages (JSON-RPC).

**Request headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request body:** JSON-RPC message (pass through unmodified)

**Processing:**

1. Extract and remap auth header (same as GET)
2. Forward the entire request body to the downstream MCP server's POST endpoint
3. Return the downstream response

**Response:** JSON (`Content-Type: application/json`)

## PKCE Verification Reference

Claude uses S256 PKCE. Verification pseudocode:

```
code_challenge_computed = base64url_no_pad(sha256(code_verifier))
valid = (code_challenge_computed == stored_code_challenge)
```

- `base64url_no_pad`: Base64 URL-safe encoding with no `=` padding
- `sha256`: Raw SHA-256 hash bytes (not hex)
- `code_verifier`: 43-128 character string using `[A-Z] [a-z] [0-9] - . _ ~`

## HTTP Status Code Summary

| Status | When |
|--------|------|
| 200 | Successful token exchange, successful MCP proxy |
| 302 | All redirects (authorize → form/downstream, callback → Claude) |
| 400 | Invalid grant, bad request params, PKCE failure |
| 401 | Missing/invalid bearer token on MCP endpoints |
| 404 | Unknown path prefix |
| 502 | Downstream MCP server error |
