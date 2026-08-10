//! Optional HS256/RS256 signature verification.
//!
//! This module is feature-gated behind the `verify` feature flag.
//! When not compiled in, calling verification functions returns
//! `CoreError::VerifyNotEnabled`.

use crate::error::CoreError;
#[cfg(feature = "verify")]
use crate::parse::{base64url_decode, parse_jwt, split_token};

/// Verify an HS256 (HMAC-SHA256) JWT signature.
///
/// Re-computes the HMAC-SHA256 of `header.payload` using the provided
/// secret and compares it against the signature in the token.
///
/// # Arguments
///
/// * `token` - The complete JWT token string (header.payload.signature).
/// * `secret` - The shared secret key bytes.
///
/// # Errors
///
/// Returns `CoreError::VerifyNotEnabled` if the `verify` feature is not
/// compiled in. Returns `CoreError::VerifyHs256Invalid` if the signature
/// does not match.
#[cfg(feature = "verify")]
pub fn verify_hs256(token: &str, secret: &[u8]) -> Result<bool, CoreError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let parsed = parse_jwt(token)?;
    if parsed.header.algorithm != "HS256" {
        return Err(CoreError::UnsupportedAlgorithm(parsed.header.algorithm));
    }
    let (header, payload, sig_b64) = split_token(token)?;

    // Decode the signature
    let expected_sig = base64url_decode(sig_b64).map_err(|_| CoreError::VerifyHs256Invalid)?;

    // Recompute HMAC-SHA256(secret, header.payload)
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| CoreError::VerifyHs256Invalid)?;

    // The HMAC input is header.payload (with the dot)
    let signing_input = format!("{header}.{payload}");
    mac.update(signing_input.as_bytes());

    // Verify in constant time
    mac.verify_slice(&expected_sig)
        .map(|()| true)
        .map_err(|_| CoreError::VerifyHs256Invalid)
}

/// Verify an RS256 (RSA-SHA256) JWT signature.
///
/// Verifies the RSASSA-PKCS1-v1_5 SHA-256 signature using a PEM-encoded
/// RSA public key.
///
/// # Arguments
///
/// * `token` - The complete JWT token string (header.payload.signature).
/// * `public_key_pem` - PEM-encoded RSA public key string (SPKI format,
///   "-----BEGIN PUBLIC KEY-----").
///
/// # Errors
///
/// Returns `CoreError::VerifyNotEnabled` if the `verify` feature is not
/// compiled in. Returns `CoreError::VerifyRs256Invalid` if the signature
/// does not match. Returns `CoreError::VerifyRs256PemError` if the PEM
/// cannot be parsed.
#[cfg(feature = "verify")]
pub fn verify_rs256(token: &str, public_key_pem: &str) -> Result<bool, CoreError> {
    use rsa::pkcs1v15::Signature;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    use rsa::{RsaPublicKey, pkcs1v15};

    let parsed = parse_jwt(token)?;
    if parsed.header.algorithm != "RS256" {
        return Err(CoreError::UnsupportedAlgorithm(parsed.header.algorithm));
    }
    let (header, payload, sig_b64) = split_token(token)?;

    // Decode the signature
    let signature_bytes = base64url_decode(sig_b64).map_err(|_| CoreError::VerifyRs256Invalid)?;

    // Parse PEM to DER, then to RSA public key
    let pem =
        pem::parse(public_key_pem).map_err(|e| CoreError::VerifyRs256PemError(e.to_string()))?;

    let public_key = RsaPublicKey::from_public_key_der(pem.contents())
        .map_err(|e| CoreError::VerifyRs256PemError(e.to_string()))?;

    // Reconstruct the signing input
    let signing_input = format!("{header}.{payload}");

    // Build the verifying key and verify
    let verifying_key: pkcs1v15::VerifyingKey<sha2::Sha256> =
        pkcs1v15::VerifyingKey::new(public_key);
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| CoreError::VerifyRs256Invalid)?;

    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map(|()| true)
        .map_err(|_| CoreError::VerifyRs256Invalid)
}

/// Stub: returns `VerifyNotEnabled` when the `verify` feature is not compiled.
#[cfg(not(feature = "verify"))]
pub fn verify_hs256(_token: &str, _secret: &[u8]) -> Result<bool, CoreError> {
    Err(CoreError::VerifyNotEnabled)
}

/// Stub: returns `VerifyNotEnabled` when the `verify` feature is not compiled.
#[cfg(not(feature = "verify"))]
pub fn verify_rs256(_token: &str, _public_key_pem: &str) -> Result<bool, CoreError> {
    Err(CoreError::VerifyNotEnabled)
}

#[cfg(test)]
#[cfg(feature = "verify")]
mod tests {
    use super::*;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    fn b64() -> base64::engine::GeneralPurpose {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    }

    /// Create a signed HS256 token for testing.
    fn make_hs256_token(header: &str, payload: &str, secret: &[u8]) -> String {
        let h = b64().encode(header);
        let p = b64().encode(payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(format!("{h}.{p}").as_bytes());
        let sig = b64().encode(mac.finalize().into_bytes());
        format!("{h}.{p}.{sig}")
    }

    /// Create a signed RS256 token and return (token, public_key_pem).
    fn make_rs256_token(header: &str, payload: &str) -> (String, String) {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let pkcs8_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

        let h = b64().encode(header);
        let p = b64().encode(payload);
        let signing_input = format!("{h}.{p}");

        let signing_key: SigningKey<Sha256> = SigningKey::new(private_key);
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = b64().encode(signature.to_bytes());

        let token = format!("{h}.{p}.{sig_b64}");
        (token, pkcs8_pem)
    }

    #[test]
    fn hs256_valid() {
        let secret = b"my-secret-key";
        let token = make_hs256_token(r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"sub":"123"}"#, secret);
        assert!(verify_hs256(&token, secret).unwrap());
    }

    #[test]
    fn hs256_wrong_key() {
        let token = make_hs256_token(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"sub":"123"}"#,
            b"correct-key",
        );
        let result = verify_hs256(&token, b"wrong-key");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "VERIFY_HS256_INVALID");
    }

    #[test]
    fn hs256_rejects_algorithm_confusion() {
        let token = make_hs256_token(
            r#"{"alg":"RS256","typ":"JWT"}"#,
            r#"{"sub":"123"}"#,
            b"my-secret-key",
        );
        let result = verify_hs256(&token, b"my-secret-key");
        assert_eq!(result.unwrap_err().code(), "UNSUPPORTED_ALGORITHM");
    }

    #[test]
    fn hs256_tampered_payload() {
        let secret = b"my-secret-key";
        let token = make_hs256_token(r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"sub":"123"}"#, secret);
        // Tamper with payload
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let tampered = format!("{}.{}.{}", parts[0], "dGFtcGVyZWQ", parts[2]);
        assert!(verify_hs256(&tampered, secret).is_err());
    }

    #[test]
    fn rs256_valid() {
        let (token, pkcs8_pem) =
            make_rs256_token(r#"{"alg":"RS256","typ":"JWT"}"#, r#"{"sub":"123"}"#);
        assert!(verify_rs256(&token, &pkcs8_pem).unwrap());
    }

    #[test]
    fn rs256_tampered() {
        let (token, pkcs8_pem) =
            make_rs256_token(r#"{"alg":"RS256","typ":"JWT"}"#, r#"{"sub":"123"}"#);
        // Tamper: replace payload segment
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let tampered = format!("{}.{}.{}", parts[0], "dGFtcGVyZWQ", parts[2]);
        assert!(verify_rs256(&tampered, &pkcs8_pem).is_err());
    }

    #[test]
    fn rs256_wrong_key() {
        let (token, _pkcs8_pem) =
            make_rs256_token(r#"{"alg":"RS256","typ":"JWT"}"#, r#"{"sub":"123"}"#);
        // Generate a different key pair
        let mut rng = rand::thread_rng();
        let other_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let other_public = RsaPublicKey::from(&other_key);
        let other_pem = other_public.to_public_key_pem(LineEnding::LF).unwrap();

        let result = verify_rs256(&token, &other_pem);
        assert!(result.is_err());
    }
}

#[cfg(test)]
#[cfg(not(feature = "verify"))]
mod tests {
    use super::*;

    #[test]
    fn verify_not_enabled() {
        let result = verify_hs256("a.b.c", b"secret");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "VERIFY_NOT_ENABLED");

        let result = verify_rs256("a.b.c", "-----BEGIN PUBLIC KEY-----");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "VERIFY_NOT_ENABLED");
    }
}
