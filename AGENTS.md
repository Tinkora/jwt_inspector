# Repository Guide for AI Agents

## Project Overview

jwt_inspector is a browser-native JWT (JSON Web Token) inspector. Parse header and payload without verifying signature (for debugging/inspection). Support HS256/RS256 signature verification with user-provided key. Color-coded claims display. All computation in WASM, keys never leave the browser.

## Architecture

```
jwt_inspector/
├── crates/
│   ├── jwt_inspector_core/       # JWT parsing, expiry checking, signature verification
│   └── jwt_inspector_web/        # WASM bridge + HTML inspector UI
├── docs/                           # Product specification
├── skills/                         # Machine-readable integration schema drafts
└── index.html                      # Product landing page
```

## Key Files for AI Context

| File | Purpose |
|------|---------|
| `crates/jwt_inspector_core/src/parse.rs` | JWT token parsing, header/payload extraction, base64url decoding |
| `crates/jwt_inspector_core/src/verify.rs` | HS256/RS256 signature verification (feature-gated) |
| `crates/jwt_inspector_core/src/error.rs` | Stable error type with machine-readable codes |
| `crates/jwt_inspector_core/src/wasm.rs` | WASM bindings (6 JS exports) |
| `crates/jwt_inspector_core/src/lib.rs` | Module declarations and public API re-exports |
| `crates/jwt_inspector_web/src/lib.rs` | WASM bridge glue |
| `crates/jwt_inspector_web/static/index.html` | Full-featured JWT inspector UI |
| `skills/jwt_inspector.md` | Agent usage workflow |
| `skills/mcp-tools.json` | MCP tool definitions |

## Build & Test Commands

```bash
# Run all tests
cargo test --workspace

# Format check
cargo fmt --all -- --check

# Lint (strict)
cargo clippy --workspace --all-targets -- -D warnings

# WASM compilation check
cargo check -p jwt_inspector_web --target wasm32-unknown-unknown

# Build Web WASM for deployment
wasm-pack build --target web crates/jwt_inspector_web
```

## Design Principles

1. **Browser-first**: All JWT parsing and verification happens in-browser via WASM
2. **Keys never leave the browser**: HMAC secrets and RSA public keys stay in WASM memory, never transmitted
3. **Parse without verification first**: Users can inspect JWT contents without providing keys
4. **Color-coded claims**: Visual distinction for standard claims (iss, sub, aud, exp, iat, nbf, jti)
5. **Human-readable timestamps**: exp/iat/nbf shown as both Unix timestamp and ISO 8601 date

## JWT Structure

```
header.payload.signature
```

- **Header**: Base64url-encoded JSON with `alg`, `typ`, `kid` fields
- **Payload**: Base64url-encoded JSON claims set
- **Signature**: Base64url-encoded HMAC/RSA signature bytes

## Error Codes (Stable Machine-Readable)

| Code | Meaning |
|------|---------|
| `PARSE_INVALID_FORMAT` | Token does not have 3 dot-separated segments |
| `PARSE_BASE64_DECODE_HEADER` | Failed to base64url-decode header |
| `PARSE_BASE64_DECODE_PAYLOAD` | Failed to base64url-decode payload |
| `PARSE_JSON_HEADER` | Failed to parse header as JSON |
| `PARSE_JSON_PAYLOAD` | Failed to parse payload as JSON |
| `EXPIRY_MISSING_EXP` | No `exp` claim in token |
| `EXPIRY_INVALID_EXP` | `exp` claim is not a valid Unix timestamp |
| `VERIFY_HS256_INVALID_KEY` | HMAC verification failed (key or signature mismatch) |
| `VERIFY_RS256_INVALID_KEY` | RSA verification failed (key format or signature mismatch) |
| `VERIFY_NOT_ENABLED` | Verify feature is not compiled in |
| `UNSUPPORTED_ALGORITHM` | Algorithm in JWT header is not HS256 or RS256 |

## Commit Language

- Write commit subjects and bodies in English and follow Conventional Commits.
- This repository-level rule overrides any global preference for another commit-message language.

## Frontend Design Requirement

- Before creating, modifying, reviewing, or debugging any HTML page or user-facing frontend, invoke the `ui-ux-pro-max` skill.
- Run the skill's required `--design-system` search before editing, followed by relevant stack and UX searches.
- If `ui-ux-pro-max` is unavailable, stop frontend work and report the missing prerequisite.
- Verify the rendered result in a real browser at 375, 768, 1024, and 1440 pixel widths, including console, keyboard, accessibility, and overflow checks.
