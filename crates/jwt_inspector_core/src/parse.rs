use base64::Engine;
use serde_json::{Map, Value};

use crate::error::CoreError;

/// Maximum token size accepted by the browser and agent-facing parser.
pub const MAX_TOKEN_BYTES: usize = 1024 * 1024;

/// Parsed JWT token with decoded header, payload, and raw signature.
#[derive(Clone, Debug)]
pub struct JwtToken {
    /// Decoded and parsed JWT header.
    pub header: JwtHeader,
    /// Decoded payload as a JSON value (claims set).
    pub payload: Value,
    /// Raw base64url-encoded signature string.
    pub signature: String,
    /// Raw base64url-encoded header segment (as found in the token).
    pub header_raw: String,
    /// Raw base64url-encoded payload segment (as found in the token).
    pub payload_raw: String,
}

/// Decoded JWT header fields.
#[derive(Clone, Debug)]
pub struct JwtHeader {
    /// Algorithm from the `alg` field (e.g. "HS256", "RS256").
    pub algorithm: String,
    /// Optional token type from the `typ` field.
    pub token_type: Option<String>,
    /// Optional key ID from the `kid` field.
    pub key_id: Option<String>,
    /// All header fields preserved as a raw JSON object.
    pub raw: Map<String, Value>,
}

/// Expiry status of a JWT token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryStatus {
    /// Token is not expired; no signature or authorization judgment is implied.
    Valid,
    /// Token has expired.
    Expired,
    /// Token expires within the next hour.
    ExpiringSoon,
    /// Token has no `exp` claim.
    NoExpiry,
}

impl ExpiryStatus {
    /// CSS class name for the status badge in the UI.
    pub const fn css_class(&self) -> &'static str {
        match self {
            Self::Valid => "exp-valid",
            Self::Expired => "exp-expired",
            Self::ExpiringSoon => "exp-soon",
            Self::NoExpiry => "exp-none",
        }
    }

    /// Human-readable Chinese label.
    pub const fn label_zh(&self) -> &'static str {
        match self {
            Self::Valid => "未过期",
            Self::Expired => "已过期",
            Self::ExpiringSoon => "即将过期",
            Self::NoExpiry => "无过期声明",
        }
    }

    /// Human-readable English label.
    pub const fn label_en(&self) -> &'static str {
        match self {
            Self::Valid => "Not Expired",
            Self::Expired => "Expired",
            Self::ExpiringSoon => "Expiring Soon",
            Self::NoExpiry => "No Expiry",
        }
    }
}

/// Canonical list of standard JWT claims that get special highlighting.
pub const STANDARD_CLAIMS: &[&str] = &["iss", "sub", "aud", "exp", "iat", "nbf", "jti"];

/// Returns true if the claim name is a standard JWT claim.
pub fn is_standard_claim(key: &str) -> bool {
    STANDARD_CLAIMS.contains(&key)
}

/// Base64url engine for JWT decoding (no padding, URL-safe alphabet).
fn b64_engine() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Decode a single base64url-encoded segment to bytes.
pub(crate) fn base64url_decode(segment: &str) -> Result<Vec<u8>, CoreError> {
    b64_engine()
        .decode(segment)
        .map_err(|e| CoreError::ParseBase64DecodeHeader(e.to_string()))
}

/// Parse a JWT token string into its three dot-separated segments.
pub(crate) fn split_token(token: &str) -> Result<(&str, &str, &str), CoreError> {
    let trimmed = token.trim();
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() != 3 {
        return Err(CoreError::ParseInvalidFormat);
    }
    Ok((parts[0], parts[1], parts[2]))
}

/// Parse a JWT token without verifying the signature.
///
/// Splits the token into its three dot-separated segments, base64url-decodes
/// the header and payload, and parses them as JSON. The signature is kept
/// in its raw base64url-encoded form.
///
/// # Errors
///
/// Returns `CoreError` if the token format is invalid, base64 decoding fails,
/// or the JSON is malformed.
pub fn parse_jwt(token: &str) -> Result<JwtToken, CoreError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(CoreError::ParseInputTooLarge);
    }
    let (header_seg, payload_seg, sig_seg) = split_token(token)?;

    // Decode header
    let header_bytes = base64url_decode(header_seg)
        .map_err(|_| CoreError::ParseBase64DecodeHeader("base64 decode failed".into()))?;
    let header_json_str =
        String::from_utf8(header_bytes).map_err(|_| CoreError::ParseHeaderNotUtf8)?;
    let header_value: Value = serde_json::from_str(&header_json_str)
        .map_err(|e| CoreError::ParseJsonHeader(e.to_string()))?;

    let header_obj = match &header_value {
        Value::Object(map) => map.clone(),
        _ => {
            return Err(CoreError::ParseJsonHeader(
                "header is not a JSON object".into(),
            ));
        }
    };

    let algorithm = header_obj
        .get("alg")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or(CoreError::MissingAlgorithm)?;

    let token_type = header_obj
        .get("typ")
        .and_then(|v| v.as_str())
        .map(String::from);

    let key_id = header_obj
        .get("kid")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Decode payload
    let payload_bytes = base64url_decode(payload_seg)
        .map_err(|_| CoreError::ParseBase64DecodePayload("base64 decode failed".into()))?;
    let payload_json_str =
        String::from_utf8(payload_bytes).map_err(|_| CoreError::ParsePayloadNotUtf8)?;
    let payload_value: Value = serde_json::from_str(&payload_json_str)
        .map_err(|e| CoreError::ParseJsonPayload(e.to_string()))?;

    // Ensure payload is an object
    if !payload_value.is_object() {
        return Err(CoreError::ParseJsonPayload(
            "payload is not a JSON object".into(),
        ));
    }

    Ok(JwtToken {
        header: JwtHeader {
            algorithm,
            token_type,
            key_id,
            raw: header_obj,
        },
        payload: payload_value,
        signature: sig_seg.to_string(),
        header_raw: header_seg.to_string(),
        payload_raw: payload_seg.to_string(),
    })
}

/// Extract the `exp` claim as a Unix timestamp (seconds since epoch).
fn extract_exp(claims: &Value) -> Result<Option<i64>, CoreError> {
    match claims.get("exp") {
        None => Ok(None),
        Some(v) => v
            .as_i64()
            .or_else(|| v.as_f64().map(|f| f as i64))
            .map(Some)
            .ok_or_else(|| CoreError::ExpiryInvalidExp(v.to_string())),
    }
}

/// Check whether a JWT token is expired.
///
/// Returns `true` if the token has an `exp` claim and that time is in the past
/// (accounting for `leeway_seconds` of clock skew tolerance).
///
/// Returns an error if there is no `exp` claim or it cannot be parsed.
pub fn is_expired(
    claims: &Value,
    leeway_seconds: i64,
    now_seconds: i64,
) -> Result<bool, CoreError> {
    let exp = extract_exp(claims)?.ok_or(CoreError::ExpiryMissingExp)?;
    let tolerated_expiry = exp.saturating_add(leeway_seconds.max(0));
    Ok(now_seconds >= tolerated_expiry)
}

/// Get the number of seconds until the token expires.
///
/// Returns `None` if the token has no `exp` claim.
/// Returns a negative value if the token has already expired.
pub fn time_to_expiry(claims: &Value, now_seconds: i64) -> Result<Option<i64>, CoreError> {
    match extract_exp(claims)? {
        None => Ok(None),
        Some(exp) => Ok(Some(exp - now_seconds)),
    }
}

/// Determine the expiry status of a token.
///
/// Returns one of:
/// - `Valid`: not expired, more than 1 hour remaining
/// - `ExpiringSoon`: not expired, but within the next hour
/// - `Expired`: `exp` is in the past (accounting for leeway)
/// - `NoExpiry`: no `exp` claim present
pub fn expiry_status(
    claims: &Value,
    leeway_seconds: i64,
    now_seconds: i64,
) -> Result<ExpiryStatus, CoreError> {
    let exp = match extract_exp(claims)? {
        Some(e) => e,
        None => return Ok(ExpiryStatus::NoExpiry),
    };

    let remaining = exp.saturating_sub(now_seconds);
    let tolerated_expiry = exp.saturating_add(leeway_seconds.max(0));

    if now_seconds >= tolerated_expiry {
        Ok(ExpiryStatus::Expired)
    } else if remaining <= 3600 {
        Ok(ExpiryStatus::ExpiringSoon)
    } else {
        Ok(ExpiryStatus::Valid)
    }
}

/// Convert a Unix timestamp (seconds) to an ISO 8601 string.
///
/// Returns "N/A" if the timestamp is out of range.
pub fn unix_to_iso8601(ts: i64) -> String {
    const SECS_PER_DAY: i64 = 86400;

    // `rem_euclid` always returns a non-negative result when divisor > 0
    let days_since_epoch = ts.div_euclid(SECS_PER_DAY);
    let secs_of_day = ts.rem_euclid(SECS_PER_DAY);

    // Algorithm from Howard Hinnant's civil_from_days
    // <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>
    let z = days_since_epoch + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month phase [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // day of month [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let year = if month <= 2 { year + 1 } else { year };

    let hours = (secs_of_day / 3600) as u32;
    let mins = ((secs_of_day % 3600) / 60) as u32;
    let secs = (secs_of_day % 60) as u32;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, mins, secs
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_token(header: &str, payload: &str, sig: &str) -> String {
        let h = b64_engine().encode(header);
        let p = b64_engine().encode(payload);
        format!("{h}.{p}.{sig}")
    }

    #[test]
    fn parse_simple_jwt() {
        let token = make_test_token(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#,
            "fake_signature",
        );
        let jwt = parse_jwt(&token).unwrap();
        assert_eq!(jwt.header.algorithm, "HS256");
        assert_eq!(jwt.header.token_type.as_deref(), Some("JWT"));
        assert_eq!(jwt.payload["sub"], "1234567890");
        assert_eq!(jwt.payload["name"], "John Doe");
        assert_eq!(jwt.signature, "fake_signature");
    }

    #[test]
    fn parse_jwt_with_kid() {
        let token = make_test_token(
            r#"{"alg":"RS256","typ":"JWT","kid":"key-1"}"#,
            r#"{"iss":"auth.example.com"}"#,
            "sig",
        );
        let jwt = parse_jwt(&token).unwrap();
        assert_eq!(jwt.header.algorithm, "RS256");
        assert_eq!(jwt.header.key_id.as_deref(), Some("key-1"));
    }

    #[test]
    fn parse_invalid_format() {
        let result = parse_jwt("not.a.jwt.extra");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "PARSE_INVALID_FORMAT");
    }

    #[test]
    fn reject_oversized_input_before_decoding() {
        let token = "x".repeat(MAX_TOKEN_BYTES + 1);
        let result = parse_jwt(&token);
        assert_eq!(result.unwrap_err().code(), "PARSE_INPUT_TOO_LARGE");
    }

    #[test]
    fn parse_missing_alg() {
        let token = make_test_token(r#"{"typ":"JWT"}"#, r#"{"sub":"1"}"#, "sig");
        let result = parse_jwt(&token);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "MISSING_ALGORITHM");
    }

    #[test]
    fn check_expiry() {
        let token = make_test_token(r#"{"alg":"HS256"}"#, r#"{"exp":2000000000}"#, "sig");
        let jwt = parse_jwt(&token).unwrap();

        // Token should be valid if now is before exp
        assert!(!is_expired(&jwt.payload, 0, 1000000000).unwrap());
        // Token should be expired if now is after exp
        assert!(is_expired(&jwt.payload, 0, 3000000000).unwrap());
        // With leeway, token should still be valid just after exp
        assert!(!is_expired(&jwt.payload, 60, 2000000030).unwrap());
    }

    #[test]
    fn check_time_to_expiry() {
        let token = make_test_token(r#"{"alg":"HS256"}"#, r#"{"exp":2000000000}"#, "sig");
        let jwt = parse_jwt(&token).unwrap();

        let tte = time_to_expiry(&jwt.payload, 1000000000).unwrap();
        assert_eq!(tte, Some(1000000000));

        let tte = time_to_expiry(&jwt.payload, 3000000000).unwrap();
        assert_eq!(tte, Some(-1000000000));
    }

    #[test]
    fn check_no_expiry() {
        let token = make_test_token(r#"{"alg":"HS256"}"#, r#"{"sub":"1"}"#, "sig");
        let jwt = parse_jwt(&token).unwrap();

        let tte = time_to_expiry(&jwt.payload, 1000000000).unwrap();
        assert_eq!(tte, None);

        let status = expiry_status(&jwt.payload, 0, 1000000000).unwrap();
        assert_eq!(status, ExpiryStatus::NoExpiry);
    }

    #[test]
    fn check_expiry_status() {
        let token = make_test_token(r#"{"alg":"HS256"}"#, r#"{"exp":2000000000}"#, "sig");
        let jwt = parse_jwt(&token).unwrap();

        // Far in the future: valid
        assert_eq!(
            expiry_status(&jwt.payload, 0, 1000000000).unwrap(),
            ExpiryStatus::Valid
        );
        // Within an hour: expiring soon
        assert_eq!(
            expiry_status(&jwt.payload, 0, 1999996500).unwrap(),
            ExpiryStatus::ExpiringSoon
        );
        // Past: expired
        assert_eq!(
            expiry_status(&jwt.payload, 0, 3000000000).unwrap(),
            ExpiryStatus::Expired
        );
    }

    #[test]
    fn expiry_status_applies_positive_leeway_after_expiration() {
        let claims = serde_json::json!({"exp": 1_000});

        assert_eq!(
            expiry_status(&claims, 60, 1_030).unwrap(),
            ExpiryStatus::ExpiringSoon
        );
        assert_eq!(
            expiry_status(&claims, 60, 1_060).unwrap(),
            ExpiryStatus::Expired
        );
    }

    #[test]
    fn unix_to_iso8601_conversion() {
        // 2024-01-15T00:00:00Z = 1705276800
        let iso = unix_to_iso8601(1705276800);
        assert_eq!(iso, "2024-01-15T00:00:00Z");

        // epoch
        let iso = unix_to_iso8601(0);
        assert_eq!(iso, "1970-01-01T00:00:00Z");
    }
}
