use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Top-level configuration parsed from TOML.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub downstream: HashMap<String, DownstreamConfig>,
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

/// Configuration for a single downstream MCP server.
#[derive(Debug, Deserialize)]
pub struct DownstreamConfig {
    pub display_name: String,
    pub downstream_url: String,
    #[serde(default = "default_auth_header_format")]
    pub auth_header_format: String,
    #[serde(default)]
    pub scopes: String,
    #[serde(flatten)]
    pub strategy: StrategyConfig,
}

/// Strategy-specific configuration, discriminated by the `strategy` field in TOML.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum StrategyConfig {
    Passthrough {
        #[serde(default)]
        auth_hint: String,
    },
    ChainedOauth {
        #[serde(flatten)]
        oauth: OAuthConfig,
    },
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct OAuthConfig {
    pub oauth_authorize_url: String,
    pub oauth_token_url: String,
    pub oauth_client_id: String,
    #[serde(default)]
    pub oauth_client_secret: String,
    #[serde(default)]
    pub oauth_scopes: String,
    #[serde(default)]
    pub oauth_supports_refresh: bool,
    #[serde(default = "default_oauth_token_accept")]
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
    for (name, ds) in &mut config.downstream {
        let env_name = format!(
            "MCP_PROXY_{}_CLIENT_SECRET",
            name.to_uppercase().replace('-', "_")
        );
        if let Ok(val) = std::env::var(&env_name) {
            if let StrategyConfig::ChainedOauth { oauth } = &mut ds.strategy {
                oauth.oauth_client_secret = val;
            }
        }
    }
}

/// Validate the entire configuration. Returns an error string on failure.
fn validate(config: &Config) -> Result<(), String> {
    validate_server(&config.server)?;
    validate_downstreams(&config.downstream)?;
    Ok(())
}

fn validate_server(server: &ServerConfig) -> Result<(), String> {
    if server.public_url.is_empty() {
        return Err("server.public_url is required".to_string());
    }

    if server.public_url.ends_with('/') {
        return Err("server.public_url must not have a trailing slash".to_string());
    }

    if server.public_url.starts_with("http://") {
        tracing::warn!(
            "server.public_url uses http:// — HTTPS is required for production deployments"
        );
    } else if !server.public_url.starts_with("https://") {
        return Err(
            "server.public_url must start with https:// (or http:// for local dev)".to_string(),
        );
    }

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

fn validate_downstreams(downstreams: &HashMap<String, DownstreamConfig>) -> Result<(), String> {
    if downstreams.is_empty() {
        return Err("At least one [downstream.*] entry is required".to_string());
    }

    let name_regex = regex_lite::Regex::new(r"^[a-z0-9-]+$").unwrap();

    for (name, ds) in downstreams {
        if !name_regex.is_match(name) {
            return Err(format!(
                "downstream '{}': name must match ^[a-z0-9-]+$ (lowercase alphanumeric and hyphens only)",
                name
            ));
        }

        if ds.display_name.is_empty() {
            return Err(format!("downstream '{}': display_name is required", name));
        }

        if ds.downstream_url.is_empty() {
            return Err(format!("downstream '{}': downstream_url is required", name));
        }
        if !ds.downstream_url.starts_with("http://") && !ds.downstream_url.starts_with("https://") {
            return Err(format!(
                "downstream '{}': downstream_url must be a valid HTTP(S) URL",
                name
            ));
        }

        if let StrategyConfig::ChainedOauth { oauth } = &ds.strategy {
            let missing: Vec<&str> = [
                ("oauth_authorize_url", oauth.oauth_authorize_url.as_str()),
                ("oauth_token_url", oauth.oauth_token_url.as_str()),
                ("oauth_client_id", oauth.oauth_client_id.as_str()),
                ("oauth_client_secret", oauth.oauth_client_secret.as_str()),
            ]
            .iter()
            .filter(|(_, v)| v.is_empty())
            .map(|(k, _)| *k)
            .collect();

            if !missing.is_empty() {
                return Err(format!(
                    "downstream '{}': chained_oauth strategy requires: {}",
                    name,
                    missing.join(", ")
                ));
            }
        }

        let valid_formats = ["Bearer", "token", "Basic", "X-API-Key"];
        if !valid_formats.contains(&ds.auth_header_format.as_str())
            && !ds.auth_header_format.starts_with("X-")
        {
            return Err(format!(
                "downstream '{}': auth_header_format '{}' is not recognized. Use one of: Bearer, token, Basic, X-API-Key, or a custom X-* header",
                name, ds.auth_header_format
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

[downstream.test]
display_name = "Test"
strategy = "passthrough"
downstream_url = "https://downstream.example.com/mcp"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.downstream.len(), 1);
        assert!(matches!(
            config.downstream["test"].strategy,
            StrategyConfig::Passthrough { .. }
        ));
    }

    #[test]
    fn test_parse_chained_oauth() {
        let toml_str = r#"
[server]
public_url = "https://example.com"
state_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[downstream.test]
display_name = "Test"
strategy = "chained_oauth"
downstream_url = "https://downstream.example.com/mcp"
oauth_authorize_url = "https://provider.com/authorize"
oauth_token_url = "https://provider.com/token"
oauth_client_id = "my-client"
oauth_client_secret = "my-secret"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(matches!(
            config.downstream["test"].strategy,
            StrategyConfig::ChainedOauth { .. }
        ));
    }

    #[test]
    fn test_passthrough_ignores_oauth_fields() {
        let toml_str = r#"
[server]
public_url = "https://example.com"
state_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[downstream.test]
display_name = "Test"
strategy = "passthrough"
downstream_url = "https://downstream.example.com/mcp"
oauth_authorize_url = "https://provider.com/authorize"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(matches!(
            config.downstream["test"].strategy,
            StrategyConfig::Passthrough { .. }
        ));
    }

    #[test]
    fn test_chained_oauth_missing_required_fields() {
        let toml_str = r#"
[server]
public_url = "https://example.com"
state_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[downstream.test]
display_name = "Test"
strategy = "chained_oauth"
downstream_url = "https://downstream.example.com/mcp"
"#;
        let result: Result<Config, _> = toml::from_str(toml_str);
        assert!(
            result.is_err(),
            "chained_oauth should require oauth_authorize_url, oauth_token_url, etc."
        );
    }

    #[test]
    fn test_invalid_name_format() {
        let toml_str = r#"
[server]
public_url = "https://example.com"
state_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

[downstream.INVALID_NAME]
display_name = "Test"
strategy = "passthrough"
downstream_url = "https://example.com"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let result = validate_downstreams(&config.downstream);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must match"));
    }
}
