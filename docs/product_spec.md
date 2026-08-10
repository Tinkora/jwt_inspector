# JWT Inspector Product Specification

## Scope

JWT Inspector is a browser-local inspection tool for debugging token shape and expiry. It decodes the header and claims without implying trust. Optional HS256 and RS256 verification is explicit and separate from parsing.

## Security boundary

- Input and keys stay in the browser and are not sent to a service.
- The parser does not build a certificate chain, validate issuer or audience, or make an authorization decision.
- Verification accepts only the algorithm named by the token header and the matching explicit verifier.
- Unsupported algorithms are reported instead of being silently downgraded.

## Compatibility

The current verifier supports HS256 shared secrets and RS256 PEM public keys. Other JOSE algorithms are intentionally outside the MVP. Tool schemas under `skills/` are integration drafts, not a running MCP server.

## Limits

The parser rejects tokens larger than 1 MiB. Callers should enforce their own output limits when processing untrusted batches.
