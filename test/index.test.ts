import { describe, expect, it } from "vitest";
import {
  buildCsp,
  CANONICAL_DIRECTIVES,
  generateNonce,
  parseCspReport,
  reportingEndpoints,
  strictPolicy,
} from "../src/index.js";

describe("@trysac/csp-builder public API and acceptance criteria", () => {
  it("acceptance 1: buildCsp with deduplication and canonical ordering", () => {
    const res = buildCsp({
      "object-src": ["'none'"],
      "default-src": ["'self'"],
      "img-src": ["'self'", "https://cdn.example", "'self'"],
    });
    expect(res).toBe("default-src 'self'; img-src 'self' https://cdn.example; object-src 'none'");
  });

  it("acceptance 2: buildCsp(strictPolicy(), { nonce: ... })", () => {
    const res = buildCsp(strictPolicy(), {
      nonce: "MTIzNDU2Nzg5MDEyMzQ1Ng==",
    });
    expect(res).toBe(
      "script-src 'nonce-MTIzNDU2Nzg5MDEyMzQ1Ng==' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'",
    );
  });

  it("acceptance 3: bare keywords, invalid sources, and unknown directives throw", () => {
    expect(() => buildCsp({ "script-src": ["self"] })).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "unquoted_keyword",
      }),
    );

    expect(() => buildCsp({ "default-src": ["https://a.example; script-src *"] })).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "invalid_source",
      }),
    );

    expect(() => buildCsp({ "script-src": ["'none'", "'self'"] })).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "invalid_source",
      }),
    );

    expect(() => buildCsp({ "connect-src": ["https://café.example"] })).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "invalid_source",
      }),
    );

    expect(() =>
      buildCsp({ "scirpt-src": ["'self'"] } as unknown as { "default-src": string[] }),
    ).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "unknown_directive",
      }),
    );
  });

  it("acceptance 4: upgrade-insecure-requests and reportingEndpoints", () => {
    const policyResult = buildCsp({
      "upgrade-insecure-requests": true,
      "report-to": "csp-endpoint",
    });
    expect(policyResult).toBe("upgrade-insecure-requests; report-to csp-endpoint");

    const header = reportingEndpoints({
      "csp-endpoint": "https://r.example/csp",
    });
    expect(header).toBe('csp-endpoint="https://r.example/csp"');

    expect(() => reportingEndpoints({ "csp-endpoint": "http://r.example/csp" })).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "invalid_endpoint",
      }),
    );
  });

  it("acceptance 5: generateNonce with deterministic generator and buildCsp nonce validation", () => {
    const nonce = generateNonce((n) => new Uint8Array(n));
    expect(nonce).toBe("AAAAAAAAAAAAAAAAAAAAAA==");

    expect(() => buildCsp({ "script-src": ["'self'"] }, { nonce: "" })).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "invalid_nonce",
      }),
    );

    expect(() => buildCsp({ "script-src": ["'self'"] }, { nonce: "'" })).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "invalid_nonce",
      }),
    );
  });

  it("acceptance 6: parse legacy application/csp-report", () => {
    const body =
      '{"csp-report":{"document-uri":"https://a.example/p","violated-directive":"script-src","effective-directive":"script-src","blocked-uri":"inline","disposition":"enforce","line-number":7}}';
    const reports = parseCspReport(body, "application/csp-report");

    expect(reports).toEqual([
      {
        documentUrl: "https://a.example/p",
        blockedUrl: "inline",
        effectiveDirective: "script-src",
        violatedDirective: "script-src",
        disposition: "enforce",
        lineNumber: 7,
      },
    ]);
  });

  it("acceptance 7: parse modern application/reports+json", () => {
    const reportsJson = JSON.stringify([
      {
        type: "csp-violation",
        url: "https://a.example/p",
        body: {
          effectiveDirective: "script-src-elem",
          blockedURL: "https://evil.example/x.js",
        },
      },
      {
        type: "deprecation",
        url: "https://a.example/p",
        body: { id: "someDeprecation" },
      },
    ]);

    const parsed = parseCspReport(reportsJson, "application/reports+json");
    expect(parsed).toHaveLength(1);
    expect(parsed[0]?.effectiveDirective).toBe("script-src-elem");
    expect(parsed[0]?.blockedUrl).toBe("https://evil.example/x.js");
  });

  it("acceptance 8: report limits, prototype safety and syntax validation", () => {
    const largeBody = "a".repeat(65_537);
    expect(() => parseCspReport(largeBody, "application/csp-report")).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "report_too_large",
      }),
    );

    expect(() => parseCspReport("[{", "application/reports+json")).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "invalid_report",
      }),
    );

    const tooMany = Array.from({ length: 101 }, () => ({
      type: "csp-violation",
      body: { effectiveDirective: "script-src" },
    }));
    expect(() => parseCspReport(JSON.stringify(tooMany), "application/reports+json")).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "invalid_report",
      }),
    );

    expect(() => parseCspReport('{"test":1}', "application/xml")).toThrowError(
      expect.objectContaining({
        name: "CspError",
        code: "invalid_report",
      }),
    );

    const protoPayload =
      '{"csp-report":{"document-uri":"https://x.example","__proto__":{"polluted":true}}}';
    const result = parseCspReport(protoPayload, "application/csp-report");
    expect(Object.getPrototypeOf(result[0])).toBeNull();
    expect("polluted" in (result[0] as object)).toBe(false);
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
  });

  it("exercises edge cases in policy building and sources", () => {
    // non-array source
    expect(() => buildCsp({ "script-src": "'self'" as unknown as string[] })).toThrowError(
      expect.objectContaining({
        code: "invalid_source",
      }),
    );

    // empty source in array
    expect(() => buildCsp({ "script-src": [""] })).toThrowError(
      expect.objectContaining({
        code: "invalid_source",
      }),
    );

    // false boolean upgrade-insecure-requests is omitted
    expect(buildCsp({ "upgrade-insecure-requests": false })).toBe("");

    // invalid boolean
    expect(() =>
      buildCsp({
        "upgrade-insecure-requests": "true" as unknown as boolean,
      }),
    ).toThrowError(expect.objectContaining({ code: "invalid_source" }));

    // report-to validation
    expect(() => buildCsp({ "report-to": "invalid space" })).toThrowError(
      expect.objectContaining({ code: "invalid_source" }),
    );
    expect(() => buildCsp({ "report-to": "" })).toThrowError(
      expect.objectContaining({ code: "invalid_source" }),
    );

    // report-uri validation
    expect(() => buildCsp({ "report-uri": ["https://example.com/csp invalid"] })).toThrowError(
      expect.objectContaining({ code: "invalid_source" }),
    );
    expect(() => buildCsp({ "report-uri": "not-array" as unknown as string[] })).toThrowError(
      expect.objectContaining({ code: "invalid_source" }),
    );

    // report-uri duplicates deduplicated
    expect(
      buildCsp({
        "report-uri": ["https://r.example/csp", "https://r.example/csp", "/report"],
      }),
    ).toBe("report-uri https://r.example/csp /report");

    // style-src gets nonce inserted first
    expect(
      buildCsp(
        { "style-src": ["'self'", "'unsafe-inline'"] },
        { nonce: "MTIzNDU2Nzg5MDEyMzQ1Ng==" },
      ),
    ).toBe("style-src 'nonce-MTIzNDU2Nzg5MDEyMzQ1Ng==' 'self' 'unsafe-inline'");

    // strictPolicy with reportTo option
    const strictWithReport = strictPolicy({ reportTo: "endpoint-group" });
    expect(strictWithReport["report-to"]).toBe("endpoint-group");
  });

  it("handles crypto default in generateNonce", () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9+/_-]{16,}={0,2}$/);
    expect(nonce.length).toBeGreaterThanOrEqual(22);
  });

  it("validates reportingEndpoints errors", () => {
    expect(() => reportingEndpoints(null as unknown as Record<string, string>)).toThrowError(
      expect.objectContaining({ code: "invalid_endpoint" }),
    );
    expect(() => reportingEndpoints({ "bad name!": "https://example.com" })).toThrowError(
      expect.objectContaining({ code: "invalid_endpoint" }),
    );
    expect(() => reportingEndpoints({ valid: 123 as unknown as string })).toThrowError(
      expect.objectContaining({ code: "invalid_endpoint" }),
    );
    expect(() => reportingEndpoints({ valid: "not-a-url" })).toThrowError(
      expect.objectContaining({ code: "invalid_endpoint" }),
    );
  });

  it("supports valid hash and scheme sources in buildCsp", () => {
    const csp = buildCsp({
      "script-src": [
        "'sha256-abc123DEF456ghi789JKL012mno345PQR678stu901v='",
        "blob:",
        "data:",
        "https://*.cdn.example.com:443/scripts",
        "*",
      ],
    });
    expect(csp).toContain("'sha256-abc123DEF456ghi789JKL012mno345PQR678stu901v='");
    expect(csp).toContain("blob:");
    expect(csp).toContain("https://*.cdn.example.com:443/scripts");
  });

  it("ensures CANONICAL_DIRECTIVES export is complete", () => {
    expect(CANONICAL_DIRECTIVES).toContain("default-src");
    expect(CANONICAL_DIRECTIVES).toContain("upgrade-insecure-requests");
  });
});
