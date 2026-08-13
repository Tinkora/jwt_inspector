# Tinkora JWT Inspector

[English](README.md)

[![在 Ko-fi 上支持 Tinkora](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/tinkora)

浏览器本地运行的 JWT 检查器。它可以解码 header、payload 和签名片段，单独显示过期状态，并在用户主动提供密钥时验证 HS256 或 RS256 签名。所有计算都在 WASM 中完成，Token 和密钥不会上传。

## 功能

- 解码 JWT 的 header、payload 和原始签名片段
- 高亮 `iss`、`sub`、`aud`、`exp`、`iat`、`nbf`、`jti` 等标准声明
- 显示有效、即将过期、已过期或没有 `exp` 的状态
- 使用共享密钥验证 HS256，使用 PEM 公钥验证 RS256
- 输入、密钥和结果仅保留在当前浏览器页
- 提供版本化的机器可读 schema，方便 Agent 集成；仓库本身不提供 MCP transport

> 解码不等于验证。解析成功的 Token 仍可能被伪造、过期或不具备授权含义。请把过期状态、签名结果和业务授权分别判断。

## 本地运行

```bash
git clone https://github.com/Tinkora/jwt_inspector.git
cd jwt_inspector
bash scripts/build_web.sh
python3 -m http.server 8080 --directory dist
```

打开 <http://localhost:8080>。

## 开发检查

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check -p jwt_inspector_web --target wasm32-unknown-unknown
```

## 文档与社区

- [产品说明](docs/product_spec.zh-CN.md) · [English specification](docs/product_spec.md)
- [贡献指南](CONTRIBUTING.md)
- [安全政策](SECURITY.md)
- [变更记录](CHANGELOG.md)

MIT License · [Tinkora](https://github.com/Tinkora)
