# Tinkora JWT Inspector

[中文说明](README.zh-CN.md)

[![CI](https://github.com/Tinkora/jwt_inspector/actions/workflows/test.yml/badge.svg)](https://github.com/Tinkora/jwt_inspector/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Rust 1.95+](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://www.rust-lang.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)

A browser-native JWT inspector. Parse, inspect, and optionally verify JWT tokens — all computation runs locally in WASM, keys never leave your browser.

## Features

- 🔍 **Instant Parse** — Paste a JWT and see header, payload, and signature decoded instantly
- 🎨 **Color-Coded Claims** — Standard claims (iss, sub, aud, exp, iat, nbf, jti) highlighted with human-readable values
- ⏰ **Expiry Status** — Green (valid), red (expired), yellow (expiring soon), gray (no exp claim)
- 🔐 **Optional Verification** — HS256 and RS256 signature verification with user-provided keys
- 🔒 **Privacy First** — All computation in WASM; HMAC secrets and RSA keys never leave the browser
- 📋 **One-Click Copy** — Copy header, payload, or signature with a single click
- 🧩 **Machine-readable schema** — Versioned tool definitions for integrating inspection into agent workflows; this repository does not ship an MCP transport.

The parser rejects inputs larger than 1 MiB. This bounds browser work for pasted or batch-provided data; it is not a guarantee that arbitrary nested JSON is safe to treat as trusted input.

> Decoding is not verification. A parsed token can be forged or expired. Treat
> the expiry and signature indicators separately, and never infer authorization
> from this tool's output.

## Quick Start

```bash
# Clone
git clone https://github.com/Tinkora/jwt_inspector.git
cd jwt_inspector

# Build the reviewed Pages distribution
bash scripts/build_web.sh

# Launch
python3 -m http.server 8080 --directory dist
```

Open `http://localhost:8080` in your browser.

## Project Structure

| Component | Description | Status |
|-----------|-------------|--------|
| `jwt_inspector_core` | JWT parsing, expiry checking, signature verification | Available |
| `jwt_inspector_web` | WASM bridge + HTML inspector UI | Available |
| `skills/` | Machine-readable integration schema draft | Draft |

## Development

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check -p jwt_inspector_web --target wasm32-unknown-unknown
```

## Docs

- [Product specification](docs/product_spec.md) · [中文产品说明](docs/product_spec.zh-CN.md)

## Community

- [Contributing](./CONTRIBUTING.md)
- [Code of Conduct](./CODE_OF_CONDUCT.md)
- [Security](./SECURITY.md)
- [Changelog](./CHANGELOG.md)

## License

MIT © [Tinkora](https://github.com/Tinkora)
