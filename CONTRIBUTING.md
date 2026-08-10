# Contributing to jwt_inspector

Thanks for your interest in jwt_inspector! Here's how to contribute.

## Development Environment

- Rust 1.95+ (stable)
- wasm-pack 0.15+
- wasm32-unknown-unknown target (`rustup target add wasm32-unknown-unknown`)

## Project Structure

```
jwt_inspector/
├── crates/
│   ├── jwt_inspector_core/       # JWT parsing, verification, WASM types
│   └── jwt_inspector_web/        # WASM bridge + HTML inspector UI
├── docs/                           # Product spec
├── skills/                         # Machine-readable integration schema drafts
└── index.html                      # Landing page
```

## Local Development

```bash
# Run tests
cargo test --workspace --all-features

# Format & lint
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Build Web WASM
bash scripts/build_web.sh

# Start local inspector
python3 -m http.server 8080 --directory dist
```

## Commit Convention

- Prefix: `feat:` / `fix:` / `docs:` / `refactor:` / `test:` / `chore:`
- Each commit should contain one logically complete change

## Pull Request Process

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Commit your changes
4. Ensure `cargo test --workspace --all-features` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` pass
5. Push to your fork (`git push origin feat/your-feature`)
6. Create a Pull Request

## Code of Conduct

Please read [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
