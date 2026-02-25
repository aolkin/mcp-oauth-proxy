#![allow(dead_code)]

/// Remap a bearer token into the downstream auth header format.
///
/// Given a downstream's `auth_header_format` config and the user's token,
/// returns `(header_name, header_value)` suitable for the downstream request.
///
/// Supported formats:
///   - `"Bearer"` → `("authorization", "Bearer <token>")`
///   - `"token"`  → `("authorization", "token <token>")`
///   - `"Basic"`  → `("authorization", "Basic <token>")`
///   - `"X-*"`    → `("<X-header>", "<token>")` (custom header, token as-is)
pub fn remap_auth_header(auth_header_format: &str, token: &str) -> (String, String) {
    if auth_header_format.starts_with("X-") {
        (auth_header_format.to_string(), token.to_string())
    } else {
        (
            "authorization".to_string(),
            format!("{auth_header_format} {token}"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bearer_format() {
        let (name, value) = remap_auth_header("Bearer", "my-token-123");
        assert_eq!(name, "authorization");
        assert_eq!(value, "Bearer my-token-123");
    }

    #[test]
    fn test_token_format() {
        let (name, value) = remap_auth_header("token", "ghp_abc123");
        assert_eq!(name, "authorization");
        assert_eq!(value, "token ghp_abc123");
    }

    #[test]
    fn test_basic_format() {
        let (name, value) = remap_auth_header("Basic", "dXNlcjpwYXNz");
        assert_eq!(name, "authorization");
        assert_eq!(value, "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn test_custom_x_api_key() {
        let (name, value) = remap_auth_header("X-API-Key", "sk-12345");
        assert_eq!(name, "X-API-Key");
        assert_eq!(value, "sk-12345");
    }

    #[test]
    fn test_custom_x_header() {
        let (name, value) = remap_auth_header("X-Custom-Auth", "my-secret");
        assert_eq!(name, "X-Custom-Auth");
        assert_eq!(value, "my-secret");
    }
}
