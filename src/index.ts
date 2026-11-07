/**
 * Public entry point for `@trysac/csp-builder`.
 *
 * Deterministic Content-Security-Policy builder with strict presets,
 * source validation, nonce generation, and dual-format report parsing.
 */

export { reportingEndpoints } from "./endpoints.js";
export { CspError, type CspErrorCode } from "./errors.js";
export { generateNonce } from "./nonce.js";
export {
  type BuildCspOptions,
  buildCsp,
  CANONICAL_DIRECTIVES,
  type CanonicalDirective,
  type CspPolicy,
  type StrictPolicyOptions,
  strictPolicy,
} from "./policy.js";
export {
  type CspViolation,
  type ParseCspReportOptions,
  parseCspReport,
} from "./reports.js";
