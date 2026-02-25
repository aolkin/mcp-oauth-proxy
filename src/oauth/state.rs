#![allow(dead_code)]

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

    fn test_secret() -> Vec<u8> {
        vec![0xCC; 32]
    }

    #[test]
    fn test_round_trip() {
        let secret = test_secret();
        let payload = json!({
            "redirect_uri": "https://claude.ai/callback",
            "code_challenge": "abc123",
            "client_state": "xyz"
        });

        let signed = sign_state(&payload, &secret);
        let recovered = verify_state(&signed, &secret).expect("should verify");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let secret = test_secret();
        let payload = json!({"key": "value"});
        let signed = sign_state(&payload, &secret);

        // Tamper: flip a character in the payload portion (before the dot)
        let dot_pos = signed.find('.').unwrap();
        let mut tampered = signed.into_bytes();
        let idx = dot_pos / 2; // somewhere in the payload
        tampered[idx] = if tampered[idx] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();

        assert!(verify_state(&tampered, &secret).is_none());
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let payload = json!({"key": "value"});
        let signed = sign_state(&payload, &[0xAA; 32]);
        assert!(verify_state(&signed, &[0xBB; 32]).is_none());
    }

    #[test]
    fn test_expired_state_rejected() {
        let secret = test_secret();
        // exp = 0 means already expired
        let payload = json!({
            "key": "value",
            "exp": 0
        });
        let signed = sign_state(&payload, &secret);
        assert!(verify_state(&signed, &secret).is_none());
    }

    #[test]
    fn test_future_expiry_accepted() {
        let secret = test_secret();
        let future_exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = json!({
            "key": "value",
            "exp": future_exp
        });
        let signed = sign_state(&payload, &secret);
        assert!(verify_state(&signed, &secret).is_some());
    }

    #[test]
    fn test_no_dot_returns_none() {
        let secret = test_secret();
        assert!(verify_state("nodothere", &secret).is_none());
    }

    #[test]
    fn test_empty_string_returns_none() {
        let secret = test_secret();
        assert!(verify_state("", &secret).is_none());
    }

    #[test]
    fn test_garbage_returns_none() {
        let secret = test_secret();
        assert!(verify_state("!!!.!!!", &secret).is_none());
    }
}
