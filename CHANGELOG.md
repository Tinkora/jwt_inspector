# Changelog

## [0.1.0] - 2026-08-11

### Added
- `jwt_inspector_core`: JWT parsing (header/payload/signature), expiry checking, HS256/RS256 verification
- `jwt_inspector_web`: WASM bridge, HTML inspector UI with dark theme
- Machine-readable integration schema draft (`skills/`)
- English-first landing page and browser inspector with a Chinese README entry
- CI workflow for all-feature tests, Clippy, WASM checks, and Pages builds
- Resource limit and algorithm-confusion regression tests

### Features
- Instant JWT header/payload decode without verification
- Color-coded claim display with human-readable timestamps
- Expiry status badge (not expired/expired/expiring soon/no exp)
- HS256 signature verification with user-provided secret
- RS256 signature verification with user-provided PEM public key
- One-click copy for header, payload, and signature sections
- All computation in WASM; keys never leave the browser
- Proposed tool schemas for programmatic JWT inspection; no MCP transport is bundled
