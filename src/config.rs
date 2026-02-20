use serde::Deserialize;
use std::path::Path;

/// Top-level configuration parsed from TOML.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(rename = "downstream")]
    pub downstreams: Vec<DownstreamConfig>,
}

/// Server-level configuration.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub public_url: String,
    /// Secret key used for HMAC-signing state parameters (chained OAuth)
    /// and AES-256-GCM encrypting stateless authorization codes.
    pub state_secret: String,
    /// TTL for encrypted authorization codes (seconds). The expiry is embedded
    /// inside the encrypted code itself — no server-side storage required.
    #[serde(default = "default_auth_code_ttl")]
    #[allow(dead_code)]
    pub auth_code_ttl: u64,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_auth_code_ttl() -> u64 {
    300
}

/// Authentication strategy for a downstream MCP server.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Passthrough,
    ChainedOauth,
}

/// Configuration for a single downstream MCP server.
#[derive(Debug, Deserialize)]
pub struct DownstreamConfig {
    pub name: String,
    pub display_name: String,
    pub strategy: Strategy,
    pub downstream_url: String,
    #[serde(default = "default_auth_header_format")]
    pub auth_header_format: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub scopes: String,

    // Passthrough-only fields
    #[serde(default)]
    #[allow(dead_code)]
    pub auth_hint: String,

    // Chained OAuth fields
    #[serde(default)]
    pub oauth_authorize_url: String,
    #[serde(default)]
    pub oauth_token_url: String,
    #[serde(default)]
    pub oauth_client_id: String,
    #[serde(default)]
    pub oauth_client_secret: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub oauth_scopes: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub oauth_supports_refresh: bool,
    #[serde(default = "default_oauth_token_accept")]
    #[allow(dead_code)]
    pub oauth_token_accept: String,
}

fn default_auth_header_format() -> String {
    "Bearer".to_string()
}

fn default_oauth_token_accept() -> String {
    "application/json".to_string()
}

/// Load and validate config from a TOML file, applying environment variable overrides.
pub fn load_config(path: &Path) -> Result<Config, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;

    let mut config: Config =
        toml::from_str(&content).map_err(|e| format!("Failed to parse TOML config: {e}"))?;

    apply_env_overrides(&mut config);
    validate(&config)?;

    Ok(config)
}

/// Apply environment variable overrides.
fn apply_env_overrides(config: &mut Config) {
    // MCP_PROXY_STATE_SECRET overrides server.state_secret
    if let Ok(val) = std::env::var("MCP_PROXY_STATE_SECRET") {
        config.server.state_secret = val;
    }

    // MCP_PROXY_<NAME>_CLIENT_SECRET overrides downstream oauth_client_secret
    for ds in &mut config.downstreams {
        let env_name = format!(
            "MCP_PROXY_{}_CLIENT_SECRET",
            ds.name.to_uppercase().replace('-', "_")
        );
        if let Ok(val) = std::env::var(&env_name) {
            ds.oauth_client_secret = val;
        }
    }
}

/// Validate the entire configuration. Returns an error string on failure.
fn validate(config: &Config) -> Result<(), String> {
    validate_server(&config.server)?;
    validate_downstreams(&config.downstreams)?;
    Ok(())
}

fn validate_server(server: &ServerConfig) -> Result<(), String> {
    // public_url must not be empty
    if server.public_url.is_empty() {
        return Err("server.public_url is required".to_string());
    }

    // public_url must not have trailing slash
    if server.public_url.ends_with('/') {
        return Err("server.public_url must not have a trailing slash".to_string());
    }

    // Warn (but allow) http:// for local dev; require https:// otherwise
    if server.public_url.starts_with("http://") {
        tracing::warn!(
            "server.public_url uses http:// — HTTPS is required for production deployments"
        );
    } else if !server.public_url.starts_with("https://") {
        return Err(
            "server.public_url must start with https:// (or http:// for local dev)".to_string(),
        );
    }

    // state_secret must decode to at least 32 bytes
    if server.state_secret.is_empty() {
        return Err("server.state_secret is required".to_string());
    }
    match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &server.state_secret,
    ) {
        Ok(bytes) => {
            if bytes.len() < 32 {
                return Err(format!(
                    "server.state_secret must be at least 32 bytes when base64-decoded (got {} bytes). Generate with: openssl rand -base64 32",
                    bytes.len()
                ));
            }
        }
        Err(e) => {
            return Err(format!("server.state_secret is not valid base64: {e}"));
        }
    }

    Ok(())
}

fn validate_downstreams(downstreams: &[DownstreamConfig]) -> Result<(), String> {
    if downstreams.is_empty() {
        return Err("At least one [[downstream]] entry is required".to_string());
    }

    let name_regex = regex_lite::Regex::new(r"^[a-z0-9-]+$").unwrap();
    let mut seen_names = std::collections::HashSet::new();

    for ds in downstreams {
        // Name format
        if !name_regex.is_match(&ds.name) {
            return Err(format!(
                "downstream '{}': name must match ^[a-z0-9-]+$ (lowercase alphanumeric and hyphens only)",
                ds.name
            ));
        }

        // Name uniqueness
        if !seen_names.insert(&ds.name) {
            return Err(format!(
                "downstream '{}': duplicate name — each downstream must have a unique name",
                ds.name
            ));
        }

        // display_name required
        if ds.display_name.is_empty() {
            return Err(format!(
                "downstream '{}': display_name is required",
                ds.name
            ));
        }

        // downstream_url must be a valid URL
        if ds.downstream_url.is_empty() {
            return Err(format!(
                "downstream '{}': downstream_url is required",
                ds.name
            ));
        }
        if !ds.downstream_url.starts_with("http://") && !ds.downstream_url.starts_with("https://") {
            return Err(format!(
                "downstream '{}': downstream_url must be a valid HTTP(S) URL",
                ds.name
            ));
        }

        // Strategy-specific validation
        if ds.strategy == Strategy::ChainedOauth {
            let missing: Vec<&str> = [
                ("oauth_authorize_url", ds.oauth_authorize_url.as_str()),
                ("oauth_token_url", ds.oauth_token_url.as_str()),
                ("oauth_client_id", ds.oauth_client_id.as_str()),
                ("oauth_client_secret", ds.oauth_client_secret.as_str()),
            ]
            .iter()
            .filter(|(_, v)| v.is_empty())
            .map(|(k, _)| *k)
            .collect();

            if !missing.is_empty() {
                return Err(format!(
                    "downstream '{}': chained_oauth strategy requires: {}",
                    ds.name,
                    missing.join(", ")
                ));
            }
        }

        // Validate auth_header_format
        let valid_formats = ["Bearer", "token", "Basic", "X-API-Key"];
        if !valid_formats.contains(&ds.auth_header_format.as_str())
            && !ds.auth_header_format.starts_with("X-")
        {
            return Err(format!(
                "downstream '{}': auth_header_format '{}' is not recognized. Use one of: Bearer, token, Basic, X-API-Key, or a custom X-* header",
                ds.name, ds.auth_header_format
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_passthrough() {
        let toml_str = r#"
[server]
public_url = "https://example.com"
state_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[[downstream]]
name = "test"
display_name = "Test"
strategy = "passthrough"
downstream_url = "https://downstream.example.com/mcp"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.downstreams.len(), 1);
        assert_eq!(config.downstreams[0].strategy, Strategy::Passthrough);
    }

    #[test]
    fn test_invalid_name_format() {
        let ds = vec![DownstreamConfig {
            name: "INVALID_NAME".to_string(),
            display_name: "Test".to_string(),
            strategy: Strategy::Passthrough,
            downstream_url: "https://example.com".to_string(),
            auth_header_format: "Bearer".to_string(),
            scopes: String::new(),
            auth_hint: String::new(),
            oauth_authorize_url: String::new(),
            oauth_token_url: String::new(),
            oauth_client_id: String::new(),
            oauth_client_secret: String::new(),
            oauth_scopes: String::new(),
            oauth_supports_refresh: false,
            oauth_token_accept: "application/json".to_string(),
        }];
        let result = validate_downstreams(&ds);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must match"));
    }
}
