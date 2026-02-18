//! Stateless encrypted authorization codes.
//!
//! Instead of an in-memory store, the authorization code itself is an AES-256-GCM
//! encrypted blob containing the downstream token, PKCE challenge, redirect URI,
//! and expiry. On `/token`, the proxy decrypts the code, verifies PKCE and expiry,
//! and returns the embedded token. Fully stateless — no HashMap, no sweeper task,
//! no concerns about multi-instance deployments.
//!
//! Format:  base64url( nonce || ciphertext || tag )
//!
//! The plaintext is JSON:
//! ```json
//! {
//!   "downstream_tokens": { ... },
//!   "pkce_challenge": "...",
//!   "redirect_uri": "...",
//!   "exp": 1234567890
//! }
//! ```

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Tokens embedded inside the encrypted authorization code.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DownstreamTokens {
    #[serde(rename = "passthrough")]
    Passthrough { access_token: String },
    #[serde(rename = "chained_oauth")]
    ChainedOAuth {
        access_token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        refresh_token: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expires_in: Option<u64>,
    },
}

/// The plaintext payload encrypted inside the authorization code.
#[derive(Debug, Serialize, Deserialize)]
struct AuthCodePayload {
    downstream_tokens: DownstreamTokens,
    pkce_challenge: String,
    redirect_uri: String,
    exp: u64,
}

/// Derive a 256-bit AES key from the server's state_secret using SHA-256.
/// The state_secret is already validated to be ≥32 bytes when base64-decoded,
/// but we hash it to get a clean 32-byte key regardless of input length.
fn derive_key(state_secret: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(state_secret);
    hash.into()
}

/// Create an encrypted authorization code containing the given grant data.
///
/// The returned string is safe to use as a URL query parameter (base64url, no padding).
pub fn create_auth_code(
    downstream_tokens: DownstreamTokens,
    pkce_challenge: &str,
    redirect_uri: &str,
    ttl_seconds: u64,
    state_secret: &[u8],
) -> Result<String, String> {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time error: {e}"))?
        .as_secs()
        + ttl_seconds;

    let payload = AuthCodePayload {
        downstream_tokens,
        pkce_challenge: pkce_challenge.to_string(),
        redirect_uri: redirect_uri.to_string(),
        exp,
    };

    let plaintext =
        serde_json::to_vec(&payload).map_err(|e| format!("failed to serialize payload: {e}"))?;

    let key = derive_key(state_secret);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("failed to create cipher: {e}"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| format!("encryption failed: {e}"))?;

    // Wire format: nonce (12 bytes) || ciphertext+tag
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    Ok(URL_SAFE_NO_PAD.encode(&blob))
}

/// Result of decrypting and validating an authorization code.
#[derive(Debug)]
pub struct ValidatedGrant {
    pub downstream_tokens: DownstreamTokens,
    pub pkce_challenge: String,
    pub redirect_uri: String,
}

/// Decrypt and validate an authorization code.
///
/// Returns the embedded grant data if the code is valid, not expired,
/// and decrypts successfully. Returns an error description otherwise.
pub fn validate_auth_code(
    code: &str,
    state_secret: &[u8],
) -> Result<ValidatedGrant, &'static str> {
    let blob = URL_SAFE_NO_PAD
        .decode(code)
        .map_err(|_| "invalid authorization code encoding")?;

    if blob.len() < 13 {
        // 12 bytes nonce + at least 1 byte ciphertext
        return Err("authorization code too short");
    }

    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = derive_key(state_secret);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "internal cipher error")?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "authorization code is invalid or tampered")?;

    let payload: AuthCodePayload =
        serde_json::from_slice(&plaintext).map_err(|_| "authorization code payload corrupt")?;

    // Check expiry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system time error")?
        .as_secs();

    if now > payload.exp {
        return Err("authorization code expired");
    }

    Ok(ValidatedGrant {
        downstream_tokens: payload.downstream_tokens,
        pkce_challenge: payload.pkce_challenge,
        redirect_uri: payload.redirect_uri,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> Vec<u8> {
        vec![0xAA; 32]
    }

    #[test]
    fn test_round_trip_passthrough() {
        let secret = test_secret();
        let code = create_auth_code(
            DownstreamTokens::Passthrough {
                access_token: "my-api-key".to_string(),
            },
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "http://localhost:9999/callback",
            300,
            &secret,
        )
        .unwrap();

        let grant = validate_auth_code(&code, &secret).unwrap();
        assert_eq!(grant.redirect_uri, "http://localhost:9999/callback");
        assert_eq!(
            grant.pkce_challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        match grant.downstream_tokens {
            DownstreamTokens::Passthrough { access_token } => {
                assert_eq!(access_token, "my-api-key");
            }
            _ => panic!("expected Passthrough variant"),
        }
    }

    #[test]
    fn test_round_trip_chained_oauth() {
        let secret = test_secret();
        let code = create_auth_code(
            DownstreamTokens::ChainedOAuth {
                access_token: "gh-access".to_string(),
                refresh_token: Some("gh-refresh".to_string()),
                expires_in: Some(28800),
            },
            "challenge123",
            "https://claude.ai/callback",
            300,
            &secret,
        )
        .unwrap();

        let grant = validate_auth_code(&code, &secret).unwrap();
        match grant.downstream_tokens {
            DownstreamTokens::ChainedOAuth {
                access_token,
                refresh_token,
                expires_in,
            } => {
                assert_eq!(access_token, "gh-access");
                assert_eq!(refresh_token.unwrap(), "gh-refresh");
                assert_eq!(expires_in.unwrap(), 28800);
            }
            _ => panic!("expected ChainedOAuth variant"),
        }
    }

    #[test]
    fn test_wrong_secret_fails() {
        let secret = test_secret();
        let code = create_auth_code(
            DownstreamTokens::Passthrough {
                access_token: "token".to_string(),
            },
            "challenge",
            "http://localhost/cb",
            300,
            &secret,
        )
        .unwrap();

        let wrong_secret = vec![0xBB; 32];
        let result = validate_auth_code(&code, &wrong_secret);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "authorization code is invalid or tampered"
        );
    }

    #[test]
    fn test_expired_code_fails() {
        let secret = test_secret();
        // Create with 0 TTL — expired immediately
        let code = create_auth_code(
            DownstreamTokens::Passthrough {
                access_token: "token".to_string(),
            },
            "challenge",
            "http://localhost/cb",
            0,
            &secret,
        )
        .unwrap();

        // Sleep briefly to ensure we're past expiry
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let result = validate_auth_code(&code, &secret);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "authorization code expired");
    }

    #[test]
    fn test_tampered_code_fails() {
        let secret = test_secret();
        let code = create_auth_code(
            DownstreamTokens::Passthrough {
                access_token: "token".to_string(),
            },
            "challenge",
            "http://localhost/cb",
            300,
            &secret,
        )
        .unwrap();

        // Flip a character in the middle of the code
        let mut tampered = code.into_bytes();
        let mid = tampered.len() / 2;
        tampered[mid] = if tampered[mid] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();

        let result = validate_auth_code(&tampered, &secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_garbage_input_fails() {
        let secret = test_secret();
        assert!(validate_auth_code("not-a-valid-code", &secret).is_err());
        assert!(validate_auth_code("", &secret).is_err());
        assert!(validate_auth_code("AAAA", &secret).is_err());
    }
}
