# Security Model

## Threat Model

### Defended
- **Header Injection**: All source expressions, nonces, and report configurations are validated against CSP3 grammar. Illegal characters like semicolons, commas, or unquoted keywords are explicitly rejected.
- **Prototype Pollution**: `parseCspReport` constructs result objects using `Object.create(null)` and ignores unknown fields, preventing malicious report payloads from polluting object prototypes.
- **Malformed Data**: Violation reports are capped at 65,536 bytes and limited to 100 entries per batch to prevent denial-of-service via resource exhaustion.
- **Misconfiguration**: Common errors such as unquoted 'self' or mixing 'none' with other sources are caught at build time.

### Not Defended
- **Weak Policy Selection**: The caller is responsible for ensuring the chosen directive values are not overly permissive (e.g., wildcards).
- **Report Authenticity**: HTTP endpoints receiving violation reports cannot verify the sender; reports must be treated as untrusted data.
- **Client-side Vulnerabilities**: CSP is a defense-in-depth mechanism; it does not replace the need for application-layer sanitization against XSS.