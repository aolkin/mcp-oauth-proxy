use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Sign a JSON payload with HMAC-SHA256, returning `base64url(json).base64url(hmac)`.
pub fn sign_state(payload: &serde_json::Value, secret: &[u8]) -> String {
    let json = serde_json::to_string(payload).expect("failed to serialize state payload");
    let payload_b64 = URL_SAFE_NO_PAD.encode(json.as_bytes());

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(json.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    format!("{payload_b64}.{sig}")
}

/// Verify an HMAC-signed state string produced by `sign_state`.
///
/// Returns `None` if the HMAC is invalid, the payload is not valid JSON,
/// or the embedded `exp` field (if present) has passed.
pub fn verify_state(state: &str, secret: &[u8]) -> Option<serde_json::Value> {
    let (payload_b64, sig_b64) = state.rsplit_once('.')?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&payload_bytes);
    let expected_sig = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    mac.verify_slice(&expected_sig).ok()?;

    let value: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    // If the payload contains an "exp" field, check it
    if let Some(exp) = value.get("exp").and_then(|v| v.as_u64()) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        if now > exp {
            return None;
        }
    }

    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &[u8] = &[0xCC; 32];

    #[test]
    fn test_round_trip() {
        let payload = json!({
            "redirect_uri": "https://claude.ai/callback",
            "code_challenge": "abc123",
            "client_state": "xyz"
        });
        let signed = sign_state(&payload, SECRET);
        assert_eq!(verify_state(&signed, SECRET).unwrap(), payload);
    }

    #[test]
    fn test_integrity_checks() {
        let payload = json!({"key": "value"});
        let signed = sign_state(&payload, SECRET);

        // Tampered payload
        let dot_pos = signed.find('.').unwrap();
        let mut tampered = signed.into_bytes();
        tampered[dot_pos / 2] ^= 1;
        assert!(verify_state(&String::from_utf8(tampered).unwrap(), SECRET).is_none());

        // Wrong secret
        let signed = sign_state(&payload, &[0xAA; 32]);
        assert!(verify_state(&signed, &[0xBB; 32]).is_none());
    }

    #[test]
    fn test_expiry() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired = sign_state(&json!({"exp": 0}), SECRET);
        assert!(verify_state(&expired, SECRET).is_none());

        let valid = sign_state(&json!({"exp": now + 3600}), SECRET);
        assert!(verify_state(&valid, SECRET).is_some());
    }

    #[test]
    fn test_malformed_input_returns_none() {
        assert!(verify_state("", SECRET).is_none());
        assert!(verify_state("nodothere", SECRET).is_none());
        assert!(verify_state("!!!.!!!", SECRET).is_none());
    }
}
