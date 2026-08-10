use thiserror::Error;

/// Stable error type for JWT inspection operations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    /// Token input exceeds the parser resource limit.
    #[error("JWT input exceeds the 1 MiB limit")]
    ParseInputTooLarge,
    /// Token does not have exactly 3 dot-separated segments.
    #[error("Invalid JWT format: expected header.payload.signature")]
    ParseInvalidFormat,

    /// Failed to base64url-decode the header segment.
    #[error("Failed to base64url-decode JWT header: {0}")]
    ParseBase64DecodeHeader(String),

    /// Failed to base64url-decode the payload segment.
    #[error("Failed to base64url-decode JWT payload: {0}")]
    ParseBase64DecodePayload(String),

    /// Header decoded bytes are not valid UTF-8.
    #[error("JWT header is not valid UTF-8")]
    ParseHeaderNotUtf8,

    /// Payload decoded bytes are not valid UTF-8.
    #[error("JWT payload is not valid UTF-8")]
    ParsePayloadNotUtf8,

    /// Failed to parse header as JSON.
    #[error("Failed to parse JWT header JSON: {0}")]
    ParseJsonHeader(String),

    /// Failed to parse payload as JSON.
    #[error("Failed to parse JWT payload JSON: {0}")]
    ParseJsonPayload(String),

    /// No `exp` claim present in the token payload.
    #[error("Token has no 'exp' (expiration) claim")]
    ExpiryMissingExp,

    /// The `exp` claim is not a valid numeric Unix timestamp.
    #[error("Token 'exp' claim is not a valid number: {0}")]
    ExpiryInvalidExp(String),

    /// HMAC verification failed — key does not match or token was tampered with.
    #[error("HS256 verification failed: invalid signature or key")]
    VerifyHs256Invalid,

    /// RSA verification failed — key does not match or token was tampered with.
    #[error("RS256 verification failed: invalid signature, key format, or algorithm mismatch")]
    VerifyRs256Invalid,

    /// PEM parsing failed for the RSA public key.
    #[error("Failed to parse RSA public key PEM: {0}")]
    VerifyRs256PemError(String),

    /// The `verify` feature is not compiled in.
    #[error("Signature verification is not enabled (compile with 'verify' feature)")]
    VerifyNotEnabled,

    /// The algorithm in the JWT header is not HS256 or RS256.
    #[error("Unsupported algorithm '{0}': only HS256 and RS256 are supported")]
    UnsupportedAlgorithm(String),

    /// The algorithm in the header is missing.
    #[error("JWT header missing required 'alg' field")]
    MissingAlgorithm,

    /// Internal error during signature verification.
    #[error("Verification error: {0}")]
    VerifyInternal(String),
}

impl CoreError {
    /// Returns a stable machine-readable error code for consumers.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ParseInputTooLarge => "PARSE_INPUT_TOO_LARGE",
            Self::ParseInvalidFormat => "PARSE_INVALID_FORMAT",
            Self::ParseBase64DecodeHeader(_) => "PARSE_BASE64_DECODE_HEADER",
            Self::ParseBase64DecodePayload(_) => "PARSE_BASE64_DECODE_PAYLOAD",
            Self::ParseHeaderNotUtf8 => "PARSE_HEADER_NOT_UTF8",
            Self::ParsePayloadNotUtf8 => "PARSE_PAYLOAD_NOT_UTF8",
            Self::ParseJsonHeader(_) => "PARSE_JSON_HEADER",
            Self::ParseJsonPayload(_) => "PARSE_JSON_PAYLOAD",
            Self::ExpiryMissingExp => "EXPIRY_MISSING_EXP",
            Self::ExpiryInvalidExp(_) => "EXPIRY_INVALID_EXP",
            Self::VerifyHs256Invalid => "VERIFY_HS256_INVALID",
            Self::VerifyRs256Invalid => "VERIFY_RS256_INVALID",
            Self::VerifyRs256PemError(_) => "VERIFY_RS256_PEM_ERROR",
            Self::VerifyNotEnabled => "VERIFY_NOT_ENABLED",
            Self::UnsupportedAlgorithm(_) => "UNSUPPORTED_ALGORITHM",
            Self::MissingAlgorithm => "MISSING_ALGORITHM",
            Self::VerifyInternal(_) => "VERIFY_INTERNAL",
        }
    }
}
