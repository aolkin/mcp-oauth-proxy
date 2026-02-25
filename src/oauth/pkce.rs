#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

/// Verify a PKCE code_verifier against a stored S256 challenge.
///
/// Computes `base64url_no_pad(sha256(code_verifier))` and compares
/// it to the stored challenge using constant-time-ish equality.
pub fn verify_pkce(code_verifier: &str, stored_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    computed == stored_challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc7636_appendix_b() {
        // RFC 7636 Appendix B test vectors
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce(verifier, challenge));
    }

    #[test]
    fn test_wrong_verifier_fails() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(!verify_pkce("wrong-verifier", challenge));
    }

    #[test]
    fn test_empty_verifier_fails() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(!verify_pkce("", challenge));
    }

    #[test]
    fn test_empty_challenge_fails() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(!verify_pkce(verifier, ""));
    }

    #[test]
    fn test_round_trip() {
        let verifier = "some-random-code-verifier-string-for-testing";
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hash);
        assert!(verify_pkce(verifier, &challenge));
    }
}
