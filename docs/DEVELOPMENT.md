# Development Guide

## Recommended Crates

```toml
[dependencies]
# Web framework
axum = { version = "0.7", features = ["macros"] }
tokio = { version = "1", features = ["full"] }

# HTTP client for downstream proxying
reqwest = { version = "0.12", features = ["stream", "json"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# OAuth / crypto
sha2 = "0.10"            # PKCE S256 verification + AES key derivation
hmac = "0.12"             # State signing (chained OAuth)
aes-gcm = "0.10"          # Encrypted authorization codes (stateless)
base64 = "0.22"           # base64url encoding
rand = "0.8"              # Nonce generation (used internally by aes-gcm)

# SSE
axum-extra = { version = "0.9", features = ["typed-header"] }
futures = "0.3"           # Stream combinators for SSE proxying
tokio-stream = "0.1"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# HTML templating (for authorize form)
askama = "0.12"           # Compile-time templates, or just use format!() for simple HTML

# CLI
clap = { version = "4", features = ["derive"] }
```

## Implementation Notes

### Router Setup (main.rs)

```rust
// Build routes dynamically from config
let app = Router::new()
    // Discovery
    .route("/.well-known/oauth-protected-resource/*path", get(well_known::protected_resource))
    .route("/.well-known/oauth-authorization-server/*path", get(well_known::authorization_server))
    // Auth flow
    .route("/authorize/*path", get(authorize::show_form).post(authorize::handle_submit))
    .route("/callback/*path", get(authorize::handle_callback))  // chained OAuth only
    // Token
    .route("/token/*path", post(token::handle))
    // MCP proxy
    .route("/mcp/*path", get(mcp_proxy::handle_sse).post(mcp_proxy::handle_post))
    .with_state(app_state);
```

All handlers extract the path suffix (e.g., `mcp/github` → `github`) and look up the downstream config from shared state.

### App State

```rust
struct AppState {
    config: Config,
    // No in-memory auth code store needed — auth codes are encrypted blobs.
    // The state_secret (decoded from config) is used for both HMAC state signing
    // and AES-256-GCM auth code encryption.
    state_secret: Vec<u8>,
    // HTTP client (reuse connections)
    http_client: reqwest::Client,
}
```

### Encrypted Authorization Codes (Stateless)

Authorization codes are AES-256-GCM encrypted blobs containing the downstream token,
PKCE challenge, redirect URI, and expiry. No server-side storage is needed.

See `src/oauth/codes.rs` for the full implementation. Usage:

```rust
use crate::oauth::codes::{create_auth_code, validate_auth_code, DownstreamTokens};

// Creating a code (in /authorize POST or /callback)
let code = create_auth_code(
    DownstreamTokens::Passthrough { access_token: user_token },
    &pkce_challenge,
    &redirect_uri,
    config.server.auth_code_ttl,
    &state_secret,
)?;

// Validating a code (in /token)
let grant = validate_auth_code(&code, &state_secret)?;
// grant.downstream_tokens — the embedded tokens to return
// grant.pkce_challenge — verify against code_verifier
// grant.redirect_uri — verify matches request
```

### PKCE Verification

```rust
use sha2::{Sha256, Digest};

fn verify_pkce(code_verifier: &str, stored_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    computed == stored_challenge
}
```

### State Signing (Chained OAuth)

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn sign_state(payload: &serde_json::Value, secret: &[u8]) -> String {
    let json = serde_json::to_string(payload).unwrap();
    let payload_b64 = URL_SAFE_NO_PAD.encode(json.as_bytes());

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(json.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    format!("{}.{}", payload_b64, sig)
}

fn verify_state(state: &str, secret: &[u8]) -> Option<serde_json::Value> {
    let (payload_b64, sig_b64) = state.rsplit_once('.')?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(&payload_bytes);
    let expected_sig = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    mac.verify_slice(&expected_sig).ok()?;

    serde_json::from_slice(&payload_bytes).ok()
}
```

### SSE Proxying

This is the trickiest part. The proxy must:
1. Accept Claude's GET request with `Accept: text/event-stream`
2. Open a streaming GET to the downstream MCP
3. Forward chunks in real-time

```rust
use axum::response::sse::{Event, Sse};
use futures::stream::{self, Stream, StreamExt};

async fn proxy_sse(
    downstream_url: &str,
    auth_header_name: &str,
    auth_header_value: &str,
    client: &reqwest::Client,
) -> Result<Sse<impl Stream<Item = Result<Event, axum::Error>>>, StatusCode> {
    let resp = client
        .get(downstream_url)
        .header(auth_header_name, auth_header_value)
        .header("Accept", "text/event-stream")
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    if !resp.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }

    // Stream raw bytes from downstream, parse into SSE events.
    // For simplicity, forward raw text lines. The MCP protocol
    // uses standard SSE framing (data: ...\n\n).
    let stream = resp
        .bytes_stream()
        .map(|result| {
            result
                .map(|bytes| Event::default().data(String::from_utf8_lossy(&bytes)))
                .map_err(|e| axum::Error::new(e))
        });

    Ok(Sse::new(stream))
}
```

**Important caveat:** The above is simplified. Real SSE parsing requires buffering lines and splitting on `\n\n` boundaries. You may want to use a lightweight SSE parsing crate or implement a small state machine that buffers incoming bytes and emits complete SSE events. Alternatively, you can skip SSE parsing entirely and just stream raw bytes through — set `Content-Type: text/event-stream` on the response and pipe bytes from downstream directly to the client via `axum::body::Body::from_stream()`. This avoids re-framing and is more reliable:

```rust
use axum::body::Body;
use axum::response::Response;

async fn proxy_sse_raw(/* ... */) -> Result<Response, StatusCode> {
    let resp = client.get(downstream_url)
        .header(auth_header_name, auth_header_value)
        .header("Accept", "text/event-stream")
        .send().await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let stream = resp.bytes_stream();
    Ok(Response::builder()
        .status(200)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap())
}
```

This raw byte passthrough approach is recommended — it's simpler and preserves the exact SSE framing from the downstream server.

### Authorize Form HTML

Keep it minimal. A single HTML page with inline CSS:

```html
<!DOCTYPE html>
<html>
<head><title>Authorize {{display_name}}</title></head>
<body>
  <h1>Connect to {{display_name}}</h1>
  <p>{{auth_hint}}</p>
  <form method="POST">
    <input type="hidden" name="state" value="{{state}}">
    <input type="hidden" name="redirect_uri" value="{{redirect_uri}}">
    <input type="hidden" name="code_challenge" value="{{code_challenge}}">
    <input type="hidden" name="code_challenge_method" value="{{code_challenge_method}}">
    <label>API Key / Token:</label>
    <input type="password" name="token" required>
    <button type="submit">Authorize</button>
  </form>
</body>
</html>
```

The hidden fields carry the OAuth parameters through the form POST so they're available when generating the auth code.

## Testing

### Manual Testing with curl

**1. Discover endpoints:**
```bash
curl https://localhost:8080/.well-known/oauth-protected-resource/mcp/linear
curl https://localhost:8080/.well-known/oauth-authorization-server/mcp/linear
```

**2. Visit authorize page:**
Open in browser:
```
https://localhost:8080/authorize/mcp/linear?\
  response_type=code&\
  client_id=test&\
  redirect_uri=http://localhost:9999/callback&\
  state=test123&\
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&\
  code_challenge_method=S256
```

(The code_challenge above corresponds to code_verifier `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`)

**3. Exchange code for token:**
```bash
curl -X POST https://localhost:8080/token/mcp/linear \
  -d "grant_type=authorization_code" \
  -d "code=<code_from_redirect>" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" \
  -d "redirect_uri=http://localhost:9999/callback" \
  -d "client_id=test"
```

**4. Test MCP proxy:**
```bash
curl -N https://localhost:8080/mcp/linear \
  -H "Authorization: Bearer <access_token>" \
  -H "Accept: text/event-stream"
```

### Integration Testing with Claude

1. Run the proxy with a real downstream MCP configured
2. In Claude's connector settings, add: `https://your-domain.com/mcp/linear`
3. Claude should:
   - Hit `.well-known` endpoints automatically
   - Redirect you to the authorize page
   - After you submit credentials, complete the OAuth flow
   - Start making MCP requests through the proxy

### Unit Test Priorities

1. **PKCE verification** — correct verifier passes, wrong verifier fails, empty strings handled
2. **State signing/verification** — round-trips correctly, tampered state rejected, expired state rejected
3. **Auth code encryption** — round-trip encrypt/decrypt, wrong secret rejected, expired codes rejected, tampered codes rejected
4. **Config validation** — missing fields caught, duplicate names caught, bad formats caught
5. **Header remapping** — each format option produces correct header name+value

## Common Pitfalls

1. **Forgetting `Accept: application/json` on GitHub token exchange.** GitHub returns form-encoded data by default. The config has `oauth_token_accept` for this.

2. **Not URL-decoding form params.** The `/token` endpoint receives `application/x-www-form-urlencoded` data. Use `axum::Form` or `serde_urlencoded`.

3. **SSE connection drops.** If the downstream MCP closes the connection, the proxy should cleanly close Claude's SSE connection too. Don't panic or hang.

4. **PKCE base64url vs base64.** PKCE uses base64url encoding **without padding**. Standard base64 with `+/=` will fail verification.

5. **State parameter passthrough.** Claude's `state` parameter must be returned unchanged in the redirect. Don't accidentally URL-encode it twice.
