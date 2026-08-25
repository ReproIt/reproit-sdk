import { createHash } from "node:crypto";

import { canonicalBytes } from "./encoding.js";

export class ManagedError extends Error {
  constructor(code, message, retryable = false) {
    super(message);
    this.name = "ManagedError";
    this.code = code;
    this.retryable = retryable;
  }
}

export function schemaInvalid(
  message = "The value does not satisfy the schema.",
) {
  return new ManagedError("SCHEMA_INVALID", message);
}

export function sameKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\u0000") ===
      [...keys].sort().join("\u0000")
  );
}

export function digestBytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function canonicalDigest(value) {
  return digestBytes(canonicalBytes(value));
}

export function validCapability(value) {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 128 &&
    /^[a-z][a-z0-9.-]*$/u.test(value)
  );
}
