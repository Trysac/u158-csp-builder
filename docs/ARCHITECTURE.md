# Architecture

`@trysac/csp-builder` is structured as a zero-dependency, modular TypeScript library providing declarative CSP building and violation report ingestion.

## Modules

- `src/errors.ts`: Unified error model defining `CspError` and machine-readable `CspErrorCode` values.
- `src/nonce.ts`: Cryptographic nonce generation using standard web crypto (`globalThis.crypto.getRandomValues`) with custom RNG injection.
- `src/sources.ts`: CSP Level 3 source-list grammar validation, detecting injection attempts, unquoted keywords, and malformed hosts.
- `src/policy.ts`: Canonical ordering, deduplication, and serialization of directives into HTTP header strings.
- `src/endpoints.ts`: Parsing and formatting for the `Reporting-Endpoints` header.
- `src/reports.ts`: Ingestion of `application/csp-report` (CSP2) and `application/reports+json` (Reporting API) payloads, enforcing field length limits and prototype neutrality (`Object.create(null)`).
