#!/usr/bin/env bash
set -euo pipefail

# RUSTSEC-2023-0071 concerns RSA private-key operations. Production code only
# parses public keys and verifies RS256 signatures. See SECURITY.md.
cargo audit --no-yanked --ignore RUSTSEC-2023-0071
