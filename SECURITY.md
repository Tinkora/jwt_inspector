# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (current) | ✅ |

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not** open a public issue.

Use GitHub Private Vulnerability Reporting from this repository's Security tab.
The project will acknowledge the report, investigate the scope, and coordinate
a fix and disclosure timeline without exposing sensitive details in a public issue.

### Scope

The following areas are within scope:

- WASM memory leaks or buffer overflows in JWT parsing
- Timing side-channels in HMAC/RSA verification
- Secret key exfiltration via JS interop
- Base64url decode panics on malicious input
- JSON parse panics on deeply nested claims

### Out of Scope

- Issues already documented as known limitations
- Theoretical attacks requiring physical access
- Issues in dependencies (please report upstream)
- Key strength or algorithm selection (the tool verifies, doesn't recommend)

## Security Model

The jwt_inspector project follows these security principles:

1. **Browser-local by design**: All parsing and verification runs in WASM in the browser. No JWT tokens, secrets, or keys are ever transmitted to a server.

2. **No server component**: There is no backend, no API, no Worker. The tool is purely static HTML + WASM.

3. **Constant-time where possible**: HMAC comparison uses `hmac` crate's built-in verification which is constant-time.

4. **No application persistence**: User-provided keys are not written to storage or sent over the network. The browser and WASM runtime control when reclaimed memory is reused; the project does not claim secure memory erasure.

5. **Panic-safe WASM**: All WASM exports return `Result<JsValue, JsValue>` with proper error messages. No panics propagate across the WASM boundary.

## Dependency Advisory Scope

`RUSTSEC-2023-0071` is narrowly ignored by `scripts/audit.sh` because it concerns RSA
private-key operations. Production code only parses public keys and verifies
RS256 signatures; it never loads a private key or performs RSA signing or
decryption. The exception must be removed when the `rsa` crate publishes a fixed
release or if the product scope starts handling private keys.
