import { CspError } from "./errors.js";

const NONCE_REGEX = /^[A-Za-z0-9+/_-]{16,}={0,2}$/;
const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Encode a Uint8Array into a standard Base64 string without relying on Node.js Buffer.
 */
function toBase64(bytes: Uint8Array): string {
  let result = "";
  const len = bytes.length;
  let i = 0;

  while (i < len) {
    const b0 = bytes[i++] ?? 0;
    const b1 = i < len ? (bytes[i++] ?? 0) : null;
    const b2 = i < len ? (bytes[i++] ?? 0) : null;

    const triplet = (b0 << 16) | ((b1 ?? 0) << 8) | (b2 ?? 0);

    result += BASE64_CHARS[(triplet >> 18) & 0x3f];
    result += BASE64_CHARS[(triplet >> 12) & 0x3f];
    result += b1 !== null ? BASE64_CHARS[(triplet >> 6) & 0x3f] : "=";
    result += b2 !== null ? BASE64_CHARS[triplet & 0x3f] : "=";
  }

  return result;
}

/**
 * Generates a cryptographically random Base64-encoded nonce (16 bytes by default).
 *
 * @param randomBytes - Optional custom byte generator for deterministic testing.
 * @returns A Base64-encoded string representing 16 random bytes.
 */
export function generateNonce(randomBytes?: (n: number) => Uint8Array): string {
  const bytes = randomBytes
    ? randomBytes(16)
    : (() => {
        const buf = new Uint8Array(16);
        if (
          typeof globalThis !== "undefined" &&
          globalThis.crypto &&
          typeof globalThis.crypto.getRandomValues === "function"
        ) {
          globalThis.crypto.getRandomValues(buf);
        } else {
          throw new CspError(
            "invalid_nonce",
            "No secure random generator available in this environment",
          );
        }
        return buf;
      })();

  if (!(bytes instanceof Uint8Array) || bytes.length !== 16) {
    throw new CspError(
      "invalid_nonce",
      "Random byte generator must produce a Uint8Array of exactly 16 bytes",
    );
  }

  return toBase64(bytes);
}

/**
 * Validates that a nonce string meets the CSP3 specification requirement.
 *
 * @param nonce - Nonce candidate.
 * @throws {CspError} With code 'invalid_nonce' if invalid.
 */
export function validateNonce(nonce: string): void {
  if (typeof nonce !== "string" || !NONCE_REGEX.test(nonce)) {
    throw new CspError(
      "invalid_nonce",
      `Invalid nonce format: must match /^[A-Za-z0-9+/_-]{16,}={0,2}$/`,
    );
  }
}
