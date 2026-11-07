# Project Information

- Name: `csp-builder`
- Objective: To provide a deterministic, type-safe builder for CSP headers and a secure parser for violation reports that mitigates injection attacks.
- Scope: CSP Level 3 serialization, strict source list validation, cryptographically secure nonce generation, `Reporting-Endpoints` formatting, and normalization of legacy and modern violation reports.
- Out-of-scope: HTTP middleware, hash computation of inline scripts, report persistence, and Trusted Types policy management.

## Factory run u158 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 4662 | 12721 | 0 | 0 | 0.0256 |
| fix-1 | gemini-3.8-flash | no | 35760 | 566 | 0 | 101138 | 0.0365 |
| audit | gemini-3.1-flash-lite | no | 63271 | 561 | 0 | 158711 | 0.0206 |
| docs | gemini-3.1-flash-lite | no | 14034 | 1267 | 0 | 0 | 0.0054 |

Total: $0.0882. Prices: Anthropic list prices.
