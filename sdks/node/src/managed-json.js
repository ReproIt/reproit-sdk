// Strict bounded protocol JSON parsing.
//
// JSON.parse silently keeps the last duplicate object key, so the protocol
// needs its own parser to fail closed on duplicate keys, non-finite numbers,
// and trailing data. Depth is bounded so untrusted input cannot exhaust the
// stack. Mirrors parse_strict_json in the Python reference.

import { Buffer } from "node:buffer";

import { schemaInvalid } from "./managed-protocol.js";

const MAX_JSON_DEPTH = 128;

// Parse bounded JSON and reject duplicate keys, NaN, and trailing data.
export function parseStrictJson(value, maximumBytes) {
  const buffer = Buffer.from(value);
  if (buffer.length > maximumBytes) {
    throw schemaInvalid();
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    throw schemaInvalid();
  }
  const parser = new StrictJsonParser(text);
  const parsed = parser.parseDocument();
  return parsed;
}

class StrictJsonParser {
  #offset = 0;
  #text;

  constructor(text) {
    this.#text = text;
  }

  parseDocument() {
    this.#skipWhitespace();
    const value = this.#parseValue(0);
    this.#skipWhitespace();
    if (this.#offset !== this.#text.length) {
      throw schemaInvalid();
    }
    return value;
  }

  #parseValue(depth) {
    if (depth > MAX_JSON_DEPTH) {
      throw schemaInvalid();
    }
    const character = this.#text[this.#offset];
    if (character === "{") return this.#parseObject(depth);
    if (character === "[") return this.#parseArray(depth);
    if (character === '"') return this.#parseString();
    if (this.#literal("true")) return true;
    if (this.#literal("false")) return false;
    if (this.#literal("null")) return null;
    return this.#parseNumber();
  }

  #parseObject(depth) {
    this.#offset += 1;
    const result = {};
    this.#skipWhitespace();
    if (this.#text[this.#offset] === "}") {
      this.#offset += 1;
      return result;
    }
    for (;;) {
      this.#skipWhitespace();
      if (this.#text[this.#offset] !== '"') {
        throw schemaInvalid();
      }
      const key = this.#parseString();
      if (Object.hasOwn(result, key)) {
        throw schemaInvalid();
      }
      this.#skipWhitespace();
      if (this.#text[this.#offset] !== ":") {
        throw schemaInvalid();
      }
      this.#offset += 1;
      this.#skipWhitespace();
      result[key] = this.#parseValue(depth + 1);
      this.#skipWhitespace();
      const next = this.#text[this.#offset];
      this.#offset += 1;
      if (next === "}") return result;
      if (next !== ",") {
        throw schemaInvalid();
      }
    }
  }

  #parseArray(depth) {
    this.#offset += 1;
    const result = [];
    this.#skipWhitespace();
    if (this.#text[this.#offset] === "]") {
      this.#offset += 1;
      return result;
    }
    for (;;) {
      this.#skipWhitespace();
      result.push(this.#parseValue(depth + 1));
      this.#skipWhitespace();
      const next = this.#text[this.#offset];
      this.#offset += 1;
      if (next === "]") return result;
      if (next !== ",") {
        throw schemaInvalid();
      }
    }
  }

  // Sticky regexes avoid re-slicing the document on every token.
  static #stringPattern =
    /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/guy;
  static #numberPattern = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/guy;

  #parseString() {
    const pattern = StrictJsonParser.#stringPattern;
    pattern.lastIndex = this.#offset;
    const match = pattern.exec(this.#text);
    if (!match) {
      throw schemaInvalid();
    }
    this.#offset = pattern.lastIndex;
    return JSON.parse(match[0]);
  }

  #parseNumber() {
    const pattern = StrictJsonParser.#numberPattern;
    pattern.lastIndex = this.#offset;
    const match = pattern.exec(this.#text);
    if (!match || match[0].length === 0) {
      throw schemaInvalid();
    }
    this.#offset = pattern.lastIndex;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) {
      throw schemaInvalid();
    }
    return value;
  }

  #literal(text) {
    if (this.#text.startsWith(text, this.#offset)) {
      this.#offset += text.length;
      return true;
    }
    return false;
  }

  #skipWhitespace() {
    while (
      this.#offset < this.#text.length &&
      " \t\n\r".includes(this.#text[this.#offset])
    ) {
      this.#offset += 1;
    }
  }
}
