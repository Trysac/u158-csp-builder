import { CspError } from "./errors.js";

const ENDPOINT_NAME_REGEX = /^[a-z0-9_-]{1,64}$/;

/**
 * Validates and formats the Reporting-Endpoints HTTP response header value.
 *
 * Syntax: endpoint_name="https://url", endpoint_name2="https://url2"
 *
 * @param endpoints - Dictionary mapping endpoint group names to https target URLs.
 * @returns The formatted Reporting-Endpoints header value.
 */
export function reportingEndpoints(endpoints: Record<string, string>): string {
  if (!endpoints || typeof endpoints !== "object" || Array.isArray(endpoints)) {
    throw new CspError("invalid_endpoint", "Endpoints must be an object map");
  }

  const entries = Object.entries(endpoints);
  const parts: string[] = [];

  for (const [name, url] of entries) {
    if (!ENDPOINT_NAME_REGEX.test(name)) {
      throw new CspError(
        "invalid_endpoint",
        `Endpoint name '${name.slice(0, 65)}' must match /^[a-z0-9_-]{1,64}$/`,
      );
    }

    if (typeof url !== "string") {
      throw new CspError("invalid_endpoint", `URL for endpoint '${name}' must be a string`);
    }

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new CspError("invalid_endpoint", `Invalid URL for endpoint '${name}'`);
    }

    if (parsed.protocol !== "https:") {
      throw new CspError(
        "invalid_endpoint",
        `Endpoint '${name}' must use the https: protocol (got '${parsed.protocol}')`,
      );
    }

    parts.push(`${name}="${parsed.toString()}"`);
  }

  return parts.join(", ");
}
