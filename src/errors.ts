/**
 * Error codes emitted by `@trysac/csp-builder`.
 */
export type CspErrorCode =
  | "unknown_directive"
  | "invalid_source"
  | "unquoted_keyword"
  | "invalid_nonce"
  | "invalid_endpoint"
  | "report_too_large"
  | "invalid_report";

/**
 * Base error class for all CSP building, validation, and parsing failures.
 */
export class CspError extends Error {
  readonly code: CspErrorCode;

  constructor(code: CspErrorCode, message: string) {
    super(message);
    this.name = "CspError";
    this.code = code;
    Object.setPrototypeOf(this, CspError.prototype);
  }
}
