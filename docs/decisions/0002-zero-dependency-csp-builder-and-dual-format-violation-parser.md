# Zero-dependency CSP builder and dual-format violation parser

Status: accepted (generated, pending human review)

## Context

Building Content-Security-Policy headers through ad-hoc string concatenation frequently introduces injection risks or invalid keyword quoting. In addition, CSP violation reports arrive in two divergent formats (legacy CSP2 and modern Reporting API) that require sanitization against prototype pollution and memory exhaustion.

## Decision

Implement a zero-dependency TypeScript library with strict source validation against the CSP3 grammar, canonical directive ordering, prototype-free violation report normalization with size limits, and a strict-dynamic default preset.

## Consequences

Callers gain type-safe CSP building and secure parsing without runtime dependencies. Unpunycoded domains or bare keyword sources are caught at build time.
