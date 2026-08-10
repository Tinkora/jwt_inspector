#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
web_crate="${repo_root}/crates/jwt_inspector_web"
static_root="${web_crate}/static"
dist_root="${repo_root}/dist"

rm -rf -- "${web_crate}/pkg" "${static_root}/pkg" "${dist_root}"
wasm-pack build "${web_crate}" --target web --release --out-dir static/pkg

mkdir -p "${dist_root}"
cp "${static_root}/index.html" "${dist_root}/index.html"
cp -R "${static_root}/pkg" "${dist_root}/pkg"
touch "${dist_root}/.nojekyll"

test -s "${dist_root}/index.html"
test -s "${dist_root}/pkg/jwt_inspector_web.js"
test -s "${dist_root}/pkg/jwt_inspector_web_bg.wasm"
