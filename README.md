# @trysac/csp-builder

Content-Security-Policy headers are built by string concatenation, so a misquoted 'self', a stray semicolon or an unvalidated host from config silently weakens or breaks the policy. Violation reports arrive in two different formats and are easy to parse unsafely. This library serialises a typed policy deterministically, rejects invalid sources, adds nonces, and normalises both report formats with size limits.

## Installation

```bash
npm install @trysac/csp-builder
```

## Usage Example

```ts
import { buildCsp, strictPolicy, generateNonce } from "@trysac/csp-builder";

const nonce = generateNonce();
const header = buildCsp(strictPolicy(), { nonce });
// => "script-src 'nonce-...' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'"
```

## Public API

- `buildCsp(policy: CspPolicy, opts?: { nonce?: string }): string`: Serializes a structured CSP object into a standard header string, enforcing canonical order and strict source-list validation.
- `strictPolicy(opts?: { reportTo?: string }): CspPolicy`: Returns a preset policy using 'strict-dynamic' with legacy browser fallbacks.
- `generateNonce(randomBytes?: (n: number) => Uint8Array): string`: Creates a cryptographically secure 16-byte base64 nonce.
- `reportingEndpoints(endpoints: Record<string, string>): string`: Builds a compliant `Reporting-Endpoints` header value.
- `parseCspReport(body: string, contentType: string, opts?: { maxBytes?: number }): CspViolation[]`: Parses and normalizes incoming violation reports, handling both legacy `application/csp-report` and modern `application/reports+json` payloads.

### Errors & Limits

- Throws `CspError` with code `'unknown_directive'`, `'invalid_source'`, `'unquoted_keyword'`, `'invalid_nonce'`, `'invalid_endpoint'`, `'report_too_large'`, or `'invalid_report'`.
- Violation reports are limited to 65,536 bytes by default and capped at 100 entries per batch.

## Why not Helmet?

`@trysac/csp-builder` is framework-free, validates every source expression against the CSP3 grammar, enforces canonical output, and provides a safe parser for violation reports, whereas general-purpose frameworks often rely on loose string concatenation.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and limits.