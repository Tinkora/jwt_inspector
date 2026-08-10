use js_sys::Reflect;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

use jwt_inspector_web::{wasm_is_expired, wasm_parse_jwt};

wasm_bindgen_test_configure!(run_in_browser);

const TOKEN: &str =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJleHAiOjQxMDI0NDQ4MDB9.ZmFrZQ";

#[wasm_bindgen_test]
fn parse_result_is_a_json_compatible_object() {
    let result = wasm_parse_jwt(TOKEN).expect("token should parse");
    let header = Reflect::get(&result, &JsValue::from_str("header"))
        .expect("header property should be readable");
    let algorithm = Reflect::get(&header, &JsValue::from_str("algorithm"))
        .expect("algorithm property should be readable");

    assert_eq!(algorithm.as_string().as_deref(), Some("HS256"));
}

#[wasm_bindgen_test]
fn expiry_result_uses_non_authorizing_status() {
    let result = wasm_is_expired(TOKEN, 0).expect("expiry should be inspectable");
    let status = Reflect::get(&result, &JsValue::from_str("status"))
        .expect("status property should be readable");

    assert_eq!(status.as_string().as_deref(), Some("not_expired"));
}
