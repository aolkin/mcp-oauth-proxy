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
    fn test_authorization_schemes() {
        for (scheme, token, expected_value) in [
            ("Bearer", "tok-123", "Bearer tok-123"),
            ("token", "ghp_abc", "token ghp_abc"),
            ("Basic", "dXNlcjpw", "Basic dXNlcjpw"),
        ] {
            let (name, value) = remap_auth_header(scheme, token);
            assert_eq!(name, "authorization");
            assert_eq!(value, expected_value);
        }
    }

    #[test]
    fn test_custom_x_headers() {
        let (name, value) = remap_auth_header("X-API-Key", "sk-12345");
        assert_eq!((name.as_str(), value.as_str()), ("X-API-Key", "sk-12345"));

        let (name, value) = remap_auth_header("X-Custom-Auth", "my-secret");
        assert_eq!(
            (name.as_str(), value.as_str()),
            ("X-Custom-Auth", "my-secret")
        );
    }
}
