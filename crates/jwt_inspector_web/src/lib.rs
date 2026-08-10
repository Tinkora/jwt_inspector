use jwt_inspector_core::CoreError;
use wasm_bindgen::prelude::*;

/// Converts a CoreError into a JsValue error carrying a stable `code` field.
fn core_err(e: CoreError) -> JsValue {
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"code".into(), &e.code().into()).ok();
    js_sys::Reflect::set(&obj, &"message".into(), &e.to_string().into()).ok();
    obj.into()
}

fn serde_wasm<T: serde::Serialize>(value: &T) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    value
        .serialize(&serializer)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {e}")))
}

fn now_seconds() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

/// Parse a JWT token without verifying the signature.
///
/// Returns a JSON object with header, payload, signature, and raw segments.
#[wasm_bindgen]
pub fn wasm_parse_jwt(token: &str) -> Result<JsValue, JsValue> {
    let jwt = jwt_inspector_core::parse_jwt(token).map_err(core_err)?;
    let result = serde_json::json!({
        "header": {
            "algorithm": jwt.header.algorithm,
            "token_type": jwt.header.token_type,
            "key_id": jwt.header.key_id,
            "raw": jwt.header.raw,
        },
        "payload": jwt.payload,
        "signature": jwt.signature,
        "header_raw": jwt.header_raw,
        "payload_raw": jwt.payload_raw,
    });
    serde_wasm(&result)
}

/// Check whether a JWT token is expired, with configurable clock skew leeway.
///
/// Returns a JSON object with expired flag, time_to_expiry, status, and human-readable labels.
#[wasm_bindgen]
pub fn wasm_is_expired(token: &str, leeway_seconds: i64) -> Result<JsValue, JsValue> {
    let jwt = jwt_inspector_core::parse_jwt(token).map_err(core_err)?;
    let now = now_seconds();

    let status = jwt_inspector_core::parse::expiry_status(&jwt.payload, leeway_seconds, now)
        .unwrap_or(jwt_inspector_core::ExpiryStatus::NoExpiry);

    let tte = jwt_inspector_core::parse::time_to_expiry(&jwt.payload, now).unwrap_or(None);

    let expired = matches!(status, jwt_inspector_core::ExpiryStatus::Expired);

    let expiry_time_iso = jwt
        .payload
        .get("exp")
        .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
        .map(jwt_inspector_core::parse::unix_to_iso8601);

    let result = serde_json::json!({
        "expired": expired,
        "time_to_expiry": tte,
        "status": status.label_en().to_lowercase().replace(' ', "_"),
        "status_label_zh": status.label_zh(),
        "status_label_en": status.label_en(),
        "status_css": status.css_class(),
        "expiry_time_iso": expiry_time_iso,
    });
    serde_wasm(&result)
}

/// Get time-to-expiry for a JWT token in seconds.
///
/// Returns null if no exp claim, negative if expired.
#[wasm_bindgen]
pub fn wasm_time_to_expiry(token: &str) -> Result<JsValue, JsValue> {
    let jwt = jwt_inspector_core::parse_jwt(token).map_err(core_err)?;
    let now = now_seconds();
    let tte = jwt_inspector_core::parse::time_to_expiry(&jwt.payload, now).unwrap_or(None);

    let expiry_time_iso = jwt
        .payload
        .get("exp")
        .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
        .map(jwt_inspector_core::parse::unix_to_iso8601);

    let result = serde_json::json!({
        "time_to_expiry": tte,
        "expiry_time_iso": expiry_time_iso,
    });
    serde_wasm(&result)
}

/// Verify an HS256 JWT signature using a shared secret.
///
/// Returns `{ "valid": true }` if the signature matches.
#[wasm_bindgen]
pub fn wasm_verify_hs256(token: &str, secret: &str) -> Result<JsValue, JsValue> {
    let valid = jwt_inspector_core::verify_hs256(token, secret.as_bytes()).map_err(core_err)?;
    let result = serde_json::json!({ "valid": valid });
    serde_wasm(&result)
}

/// Verify an RS256 JWT signature using a PEM-encoded RSA public key.
///
/// Returns `{ "valid": true }` if the signature matches.
#[wasm_bindgen]
pub fn wasm_verify_rs256(token: &str, public_key_pem: &str) -> Result<JsValue, JsValue> {
    let valid = jwt_inspector_core::verify_rs256(token, public_key_pem).map_err(core_err)?;
    let result = serde_json::json!({ "valid": valid });
    serde_wasm(&result)
}
