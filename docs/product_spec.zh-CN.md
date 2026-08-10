# jwt_inspector 产品规格

## 产品一句话

浏览器本地运行的 JWT (JSON Web Token) 检查器。无需上传，在浏览器中解码 Token，并在用户明确提供匹配密钥时单独验证 HS256/RS256 签名。解码结果不代表信任或授权。

## 目标用户

- 需要快速调试 JWT Token 的开发者和运维人员
- 希望在不信任的在线服务中检查 JWT 内容的安全工程师
- API 集成测试时需要验证 token 声明的前后端开发者
- 需要使用版本化机器可读 schema 接入 Agent 工作流的开发者

## 核心体验

1. 用户粘贴 JWT Token 到输入框
2. 立即解码 Header 和 Payload，无需密钥
3. 颜色标记的标准声明（iss, sub, aud, exp, iat, nbf, jti）
4. 过期状态徽章：绿色（有效）、红色（已过期）、黄色（即将过期）、灰色（无过期声明）
5. 可选粘贴密钥进行签名验证（HS256 / RS256）
6. 一键复制 Header、Payload、Signature
7. 所有计算在浏览器 WASM 中完成
8. 仓库不提供 MCP transport；`skills/` 仅是集成契约草案

## 功能详情

### JWT 解析（无需密钥）

- **Header**: 解码并格式化显示 `alg`、`typ`、`kid` 等字段
- **Payload**: 解码并格式化显示所有声明
- **Signature**: 显示原始 base64url 编码的签名
- **过期检查**: 
  - `is_expired`: 考虑时钟偏差（leeway_seconds）判断是否过期
  - `time_to_expiry`: 返回距离过期的秒数（负数表示已过期）
  - 时间比较使用 `js_sys::Date::now()` 获取浏览器当前时间

### 签名验证（需要密钥）

- **HS256**: 使用用户提供的共享密钥进行 HMAC-SHA256 验证
- **RS256**: 使用用户提供的 PEM 格式公钥进行 RSA-SHA256 验证
- 验证在 WASM 中完成，密钥和 token 永不离开浏览器
- HS256 验证器只接受 `alg=HS256`，RS256 验证器只接受 `alg=RS256`，防止算法混淆

### 声明高亮

以下标准声明会被特殊标记和格式化显示：

| 声明 | 显示方式 |
|------|---------|
| `iss` (Issuer) | 发行者，显示为字符串 |
| `sub` (Subject) | 主题，显示为字符串 |
| `aud` (Audience) | 接收方，支持字符串或数组 |
| `exp` (Expiration) | 过期时间，显示 Unix 时间戳和 ISO 8601 日期 |
| `iat` (Issued At) | 签发时间，显示 Unix 时间戳和 ISO 8601 日期 |
| `nbf` (Not Before) | 生效时间，显示 Unix 时间戳和 ISO 8601 日期 |
| `jti` (JWT ID) | Token 唯一标识符 |

## 输出

- 解码后的 Header JSON（彩色格式化）
- 解码后的 Payload JSON（彩色格式化，声明高亮）
- 原始 Signature 字符串
- 过期状态（not_expired / expired / expiring_soon / no_expiry）
- 验证结果（可选，verified / invalid_signature / invalid_key）

## 隐私模式

- 所有解析和验证在浏览器 WASM 中本地执行
- 无后端服务、无 API 调用、无 Worker
- 应用不把密钥写入持久化存储，也不发送到网络
- 浏览器和 WASM runtime 决定内存何时重用；项目不宣称完成安全内存擦除
- Parser 拒绝超过 1 MiB 的输入，以限制浏览器资源消耗

## 非目标

- 不创建或签发新的 JWT Token
- 不提供密钥生成功能
- 不支持 ES256 / PS256 / EdDSA（首版仅 HS256 / RS256）
- 不加解密 JWE（JSON Web Encryption）
- 不验证 iss/aud 是否匹配（仅显示内容）
- 不自动从 JWKS 端点获取密钥
- 不构建证书链、不验证 issuer/audience、不做业务授权判断

## 验收标准

- 粘贴任意格式良好的 JWT 即刻显示解码后的 Header 和 Payload
- 时间声明（exp/iat/nbf）正确转换为人类可读的 ISO 8601 格式
- 过期检查考虑可配置的时钟偏差
- HS256 验证使用已知密钥对返回正确结果
- RS256 验证使用已知密钥对返回正确结果
- 无效 Token 返回清晰的错误信息（不是 panic）
- 当前发布门禁在 Chromium 四个视口验证关键流程；Firefox 与 Safari 兼容性在取得独立验证前不作完整承诺
- 页面只加载同源 HTML、JavaScript 和 WASM，不请求外部服务
