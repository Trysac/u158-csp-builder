import { CspError } from "./errors.js";

export const VALID_KEYWORD_SOURCES = new Set([
  "'self'",
  "'none'",
  "'unsafe-inline'",
  "'unsafe-eval'",
  "'strict-dynamic'",
  "'unsafe-hashes'",
  "'report-sample'",
  "'wasm-unsafe-eval'",
]);

export const UNQUOTED_KEYWORDS = new Set([
  "self",
  "none",
  "unsafe-inline",
  "unsafe-eval",
  "strict-dynamic",
  "unsafe-hashes",
  "report-sample",
  "wasm-unsafe-eval",
]);

const SCHEME_SOURCE_REGEX = /^[a-z][a-z0-9+.-]*:$/i;
const NONCE_SOURCE_REGEX = /^'nonce-[A-Za-z0-9+/_-]{16,}={0,2}'$/;
const HASH_SOURCE_REGEX = /^'(?:sha256|sha384|sha512)-[A-Za-z0-9+/]+=*'$/;

// Host regex: optional scheme (scheme://), host (* or optional *. + domain labels), optional port (:port or :*), optional path
const HOST_SOURCE_REGEX =
  /^(?:([a-z][a-z0-9+.-]*):\/\/)?(\*|(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*)(?::([0-9]+|\*))?(\/.*)?$/i;

/**
 * Validates a single source expression per CSP3 specification.
 *
 * @param source - Source expression to validate.
 * @throws {CspError} With 'unquoted_keyword' or 'invalid_source'.
 */
export function validateSource(source: string): void {
  if (typeof source !== "string" || source.length === 0) {
    throw new CspError("invalid_source", "Source expression cannot be empty");
  }

  // Check for bare keyword names (missing quotes)
  if (UNQUOTED_KEYWORDS.has(source.toLowerCase())) {
    throw new CspError("unquoted_keyword", `Keyword '${source}' must be enclosed in single quotes`);
  }

  // Any whitespace, semicolon, comma, or non-ASCII character is rejected
  if (/[\s;,]/.test(source) || /[^\x20-\x7E]/.test(source)) {
    throw new CspError(
      "invalid_source",
      `Source '${source.slice(0, 50)}' contains forbidden characters`,
    );
  }

  // Check valid keyword sources
  if (source.startsWith("'") && source.endsWith("'")) {
    const lower = source.toLowerCase();
    if (VALID_KEYWORD_SOURCES.has(lower)) {
      return;
    }
    if (NONCE_SOURCE_REGEX.test(source)) {
      return;
    }
    if (HASH_SOURCE_REGEX.test(source)) {
      return;
    }
    throw new CspError(
      "invalid_source",
      `Invalid quoted keyword or source: '${source.slice(0, 50)}'`,
    );
  }

  // Check if quotes exist anywhere inside a non-quoted string
  if (source.includes("'")) {
    throw new CspError(
      "invalid_source",
      `Unexpected quote character in source '${source.slice(0, 50)}'`,
    );
  }

  // Scheme source: e.g. https:, data:, blob:
  if (SCHEME_SOURCE_REGEX.test(source)) {
    return;
  }

  // Host source check
  const match = source.match(HOST_SOURCE_REGEX);
  if (match) {
    const hostPart = match[2];
    if (hostPart) {
      if (hostPart === "*") {
        return;
      }
      const labels = hostPart.startsWith("*.") ? hostPart.slice(2).split(".") : hostPart.split(".");
      const validLabels = labels.every(
        (label) => label.length > 0 && !label.startsWith("-") && !label.endsWith("-"),
      );
      if (validLabels) {
        return;
      }
    }
  }

  throw new CspError("invalid_source", `Unrecognized source expression '${source.slice(0, 50)}'`);
}
