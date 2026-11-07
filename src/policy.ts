import { CspError } from "./errors.js";
import { validateNonce } from "./nonce.js";
import { validateSource } from "./sources.js";

export const CANONICAL_DIRECTIVES = [
  "default-src",
  "script-src",
  "style-src",
  "img-src",
  "connect-src",
  "font-src",
  "object-src",
  "media-src",
  "frame-src",
  "worker-src",
  "manifest-src",
  "base-uri",
  "form-action",
  "frame-ancestors",
  "upgrade-insecure-requests",
  "report-uri",
  "report-to",
] as const;

export type CanonicalDirective = (typeof CANONICAL_DIRECTIVES)[number];

export const CANONICAL_DIRECTIVE_SET = new Set<string>(CANONICAL_DIRECTIVES);

export interface CspPolicy {
  "default-src"?: string[];
  "script-src"?: string[];
  "style-src"?: string[];
  "img-src"?: string[];
  "connect-src"?: string[];
  "font-src"?: string[];
  "object-src"?: string[];
  "media-src"?: string[];
  "frame-src"?: string[];
  "worker-src"?: string[];
  "manifest-src"?: string[];
  "base-uri"?: string[];
  "form-action"?: string[];
  "frame-ancestors"?: string[];
  "upgrade-insecure-requests"?: boolean;
  "report-uri"?: string[];
  "report-to"?: string;
  [directive: string]: unknown;
}

export interface BuildCspOptions {
  nonce?: string;
}

export interface StrictPolicyOptions {
  reportTo?: string;
}

/**
 * Generates a strict CSP preset aligned with modern security practices.
 *
 * Uses `'strict-dynamic'` alongside `https:` and `'unsafe-inline'` fallbacks for legacy browsers,
 * with `'object-src': ["'none'"]` and `'base-uri': ["'none'"].
 *
 * @param opts - Options including optional `reportTo` directive name.
 * @returns A CspPolicy instance configured for strict mode.
 */
export function strictPolicy(opts?: StrictPolicyOptions): CspPolicy {
  const policy: CspPolicy = {
    "script-src": ["'strict-dynamic'", "https:", "'unsafe-inline'"],
    "object-src": ["'none'"],
    "base-uri": ["'none'"],
  };
  if (opts?.reportTo) {
    policy["report-to"] = opts.reportTo;
  }
  return policy;
}

/**
 * Validates a list of source expressions for a directive.
 * Enforces that if "'none'" is present, it must be the only source.
 * De-duplicates sources while preserving the order of first occurrence.
 */
function normalizeSourceList(directive: string, sources: string[]): string[] {
  const unique: string[] = [];
  const seen = new Set<string>();

  for (const src of sources) {
    validateSource(src);
    if (!seen.has(src)) {
      seen.add(src);
      unique.push(src);
    }
  }

  if (unique.includes("'none'") && unique.length > 1) {
    throw new CspError(
      "invalid_source",
      `Directive '${directive}' has ''none'' combined with other sources`,
    );
  }

  return unique;
}

/**
 * Builds a Content-Security-Policy header string from a structured policy object.
 *
 * @param policy - CSP policy directive definitions.
 * @param opts - Build options including optional dynamic nonce.
 * @returns Serialized CSP header string.
 */
export function buildCsp(policy: CspPolicy, opts?: BuildCspOptions): string {
  if (!policy || typeof policy !== "object") {
    throw new CspError("unknown_directive", "Policy must be an object");
  }

  // Check for unknown directives
  for (const key of Object.keys(policy)) {
    if (!CANONICAL_DIRECTIVE_SET.has(key)) {
      throw new CspError("unknown_directive", `Unknown CSP directive: '${key.slice(0, 50)}'`);
    }
  }

  let formattedNonce: string | null = null;
  if (opts?.nonce !== undefined) {
    validateNonce(opts.nonce);
    formattedNonce = `'nonce-${opts.nonce}'`;
  }

  const directiveOutputs: string[] = [];

  for (const directive of CANONICAL_DIRECTIVES) {
    const value = policy[directive];
    if (value === undefined || value === null) {
      continue;
    }

    if (directive === "upgrade-insecure-requests") {
      if (typeof value !== "boolean") {
        throw new CspError(
          "invalid_source",
          "upgrade-insecure-requests directive value must be a boolean",
        );
      }
      if (value === true) {
        directiveOutputs.push("upgrade-insecure-requests");
      }
      continue;
    }

    if (directive === "report-to") {
      if (typeof value !== "string" || value.trim() === "") {
        throw new CspError(
          "invalid_source",
          "report-to directive must be a non-empty string token",
        );
      }
      const trimmed = value.trim();
      if (/\s/.test(trimmed)) {
        throw new CspError(
          "invalid_source",
          "report-to directive token must not contain whitespace",
        );
      }
      directiveOutputs.push(`report-to ${trimmed}`);
      continue;
    }

    if (directive === "report-uri") {
      if (!Array.isArray(value)) {
        throw new CspError("invalid_source", "report-uri directive value must be an array of URIs");
      }
      const uris: string[] = [];
      const seen = new Set<string>();
      for (const uri of value) {
        if (typeof uri !== "string" || uri.trim() === "" || /\s/.test(uri)) {
          throw new CspError(
            "invalid_source",
            `Invalid report-uri entry: '${String(uri).slice(0, 50)}'`,
          );
        }
        if (!seen.has(uri)) {
          seen.add(uri);
          uris.push(uri);
        }
      }
      if (uris.length > 0) {
        directiveOutputs.push(`report-uri ${uris.join(" ")}`);
      }
      continue;
    }

    // Standard source-list directives
    if (!Array.isArray(value)) {
      throw new CspError(
        "invalid_source",
        `Directive '${directive}' value must be an array of source strings`,
      );
    }

    const rawSources = [...value];
    if (formattedNonce && (directive === "script-src" || directive === "style-src")) {
      rawSources.unshift(formattedNonce);
    }

    const normalizedSources = normalizeSourceList(directive, rawSources);
    if (normalizedSources.length > 0) {
      directiveOutputs.push(`${directive} ${normalizedSources.join(" ")}`);
    }
  }

  return directiveOutputs.join("; ");
}
