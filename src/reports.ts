import { CspError } from "./errors.js";

const DEFAULT_MAX_BYTES = 65_536;
const MAX_STRING_LENGTH = 2_048;
const MAX_REPORT_ENTRIES = 100;

export interface CspViolation {
  documentUrl?: string;
  referrer?: string;
  blockedUrl?: string;
  effectiveDirective?: string;
  violatedDirective?: string;
  originalPolicy?: string;
  disposition?: "enforce" | "report";
  statusCode?: number;
  sourceFile?: string;
  lineNumber?: number;
  columnNumber?: number;
  sample?: string;
}

export interface ParseCspReportOptions {
  maxBytes?: number;
}

function sanitizeString(val: unknown): string | undefined {
  if (typeof val !== "string") return undefined;
  return val.slice(0, MAX_STRING_LENGTH);
}

function sanitizeInt(val: unknown): number | undefined {
  if (typeof val === "number" && Number.isInteger(val) && val >= 0) {
    return val;
  }
  return undefined;
}

function sanitizeDisposition(val: unknown): "enforce" | "report" | undefined {
  if (val === "enforce" || val === "report") {
    return val;
  }
  return undefined;
}

/**
 * Parses a legacy CSP Level 2 violation report (application/csp-report).
 */
function parseLegacyReport(raw: Record<string, unknown>): CspViolation[] {
  const reportData = raw["csp-report"];
  if (!reportData || typeof reportData !== "object" || Array.isArray(reportData)) {
    throw new CspError("invalid_report", "Missing or invalid 'csp-report' object in report body");
  }

  const d = reportData as Record<string, unknown>;
  const violation: CspViolation = Object.create(null);

  const doc = sanitizeString(d["document-uri"]);
  if (doc !== undefined) violation.documentUrl = doc;

  const ref = sanitizeString(d.referrer);
  if (ref !== undefined) violation.referrer = ref;

  const blocked = sanitizeString(d["blocked-uri"]);
  if (blocked !== undefined) violation.blockedUrl = blocked;

  const effective = sanitizeString(d["effective-directive"]);
  const violated = sanitizeString(d["violated-directive"]);

  if (effective !== undefined) {
    violation.effectiveDirective = effective;
  } else if (violated !== undefined) {
    violation.effectiveDirective = violated;
  }

  if (violated !== undefined) violation.violatedDirective = violated;

  const original = sanitizeString(d["original-policy"]);
  if (original !== undefined) violation.originalPolicy = original;

  const disp = sanitizeDisposition(d.disposition);
  if (disp !== undefined) violation.disposition = disp;

  const status = sanitizeInt(d["status-code"]);
  if (status !== undefined) violation.statusCode = status;

  const srcFile = sanitizeString(d["source-file"]);
  if (srcFile !== undefined) violation.sourceFile = srcFile;

  const line = sanitizeInt(d["line-number"]);
  if (line !== undefined) violation.lineNumber = line;

  const col = sanitizeInt(d["column-number"]);
  if (col !== undefined) violation.columnNumber = col;

  const sample = sanitizeString(d["script-sample"]);
  if (sample !== undefined) violation.sample = sample;

  return [violation];
}

/**
 * Parses a Reporting API violation report (application/reports+json).
 */
function parseReportingApiReport(items: unknown[]): CspViolation[] {
  if (items.length > MAX_REPORT_ENTRIES) {
    throw new CspError(
      "invalid_report",
      `Report batch exceeds limit of ${MAX_REPORT_ENTRIES} entries`,
    );
  }

  const violations: CspViolation[] = [];

  for (const item of items) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      continue;
    }
    const reportObj = item as Record<string, unknown>;
    if (reportObj.type !== "csp-violation") {
      continue;
    }

    const b = reportObj.body;
    if (!b || typeof b !== "object" || Array.isArray(b)) {
      continue;
    }
    const body = b as Record<string, unknown>;
    const violation: CspViolation = Object.create(null);

    const doc = sanitizeString(body.documentURL ?? reportObj.url);
    if (doc !== undefined) violation.documentUrl = doc;

    const ref = sanitizeString(body.referrer);
    if (ref !== undefined) violation.referrer = ref;

    const blocked = sanitizeString(body.blockedURL);
    if (blocked !== undefined) violation.blockedUrl = blocked;

    const effective = sanitizeString(body.effectiveDirective);
    const violated = sanitizeString(body.violatedDirective);

    if (effective !== undefined) {
      violation.effectiveDirective = effective;
    } else if (violated !== undefined) {
      violation.effectiveDirective = violated;
    }

    if (violated !== undefined) violation.violatedDirective = violated;

    const original = sanitizeString(body.originalPolicy);
    if (original !== undefined) violation.originalPolicy = original;

    const disp = sanitizeDisposition(body.disposition);
    if (disp !== undefined) violation.disposition = disp;

    const status = sanitizeInt(body.statusCode);
    if (status !== undefined) violation.statusCode = status;

    const srcFile = sanitizeString(body.sourceFile);
    if (srcFile !== undefined) violation.sourceFile = srcFile;

    const line = sanitizeInt(body.lineNumber);
    if (line !== undefined) violation.lineNumber = line;

    const col = sanitizeInt(body.columnNumber);
    if (col !== undefined) violation.columnNumber = col;

    const sample = sanitizeString(body.sample);
    if (sample !== undefined) violation.sample = sample;

    violations.push(violation);
  }

  return violations;
}

/**
 * Parses and normalizes CSP violation reports from untrusted HTTP request bodies.
 *
 * Supports both legacy `application/csp-report` and modern Reporting API `application/reports+json`.
 * Media type parameters (such as `; charset=utf-8`) are stripped and ignored.
 *
 * @param body - Serialized JSON report payload.
 * @param contentType - Incoming Content-Type header string.
 * @param opts - Options including configurable maximum payload size limit in bytes.
 * @returns List of normalized CspViolation records.
 */
export function parseCspReport(
  body: string,
  contentType: string,
  opts?: ParseCspReportOptions,
): CspViolation[] {
  const maxBytes = opts?.maxBytes ?? DEFAULT_MAX_BYTES;

  if (typeof body !== "string") {
    throw new CspError("invalid_report", "Report body must be a string");
  }

  const byteLength = new TextEncoder().encode(body).length;
  if (byteLength > maxBytes) {
    throw new CspError(
      "report_too_large",
      `Report body exceeds maximum allowed size of ${maxBytes} bytes`,
    );
  }

  if (typeof contentType !== "string") {
    throw new CspError("invalid_report", "Content-Type header must be a string");
  }

  const mediaType = contentType.split(";")[0]?.trim().toLowerCase();

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new CspError("invalid_report", "Report body is not valid JSON");
  }

  if (mediaType === "application/csp-report") {
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new CspError("invalid_report", "Expected JSON object for application/csp-report");
    }
    return parseLegacyReport(parsed as Record<string, unknown>);
  }

  if (mediaType === "application/reports+json") {
    if (!Array.isArray(parsed)) {
      throw new CspError("invalid_report", "Expected JSON array for application/reports+json");
    }
    return parseReportingApiReport(parsed);
  }

  throw new CspError(
    "invalid_report",
    `Unsupported Content-Type for CSP report: '${mediaType ?? ""}'`,
  );
}
