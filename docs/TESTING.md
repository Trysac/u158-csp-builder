# Testing Strategy

Tests are located in `test/index.test.ts` and cover the following:

- **Acceptance Criteria**: Verify that `buildCsp` correctly orders directives, deduplicates sources, and serializes correctly.
- **Strict Policy Integration**: Validates that `strictPolicy()` generates the correct structure and accepts a `reportTo` override.
- **Invalid Input Handling**: Confirms that bare keywords (e.g., `self`), invalid source characters, unknown directives, and mixed `none`/other sources trigger the correct `CspError` codes.
- **Reporting Logic**: Verifies both legacy `application/csp-report` and modern `application/reports+json` formats, including prototype safety checks and batch size limits.
- **Nonce Security**: Ensures `generateNonce` uses a secure generator and that `buildCsp` validates nonce formats strictly.
- **Edge Cases**: Validates `reportingEndpoints` URL protocol constraints and `upgrade-insecure-requests` boolean handling.

All tests are executed via `vitest` with V8 coverage enabled.