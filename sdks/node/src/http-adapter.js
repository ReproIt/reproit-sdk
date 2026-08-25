import { EventEmitter, errorMonitor } from "node:events";
import { createRequire } from "node:module";
import { Readable } from "node:stream";

import { canonicalBytes } from "./encoding.js";
import {
  currentOperationContext,
  markOperationUnowned,
} from "./engine-operation.js";
import {
  dependencyRequest,
  dependencyResponse,
  startDependency,
} from "./semantic-dependency.js";

const require = createRequire(import.meta.url);
const httpModule = require("node:http");
const httpsModule = require("node:https");
const MAX_BODY_BYTES = 16 * 1_024;
const MAX_HEADER_BYTES = 8 * 1_024;
const MAX_HEADER_FIELDS = 64;
const MAX_TARGET_BYTES = 8 * 1_024;
const PAYLOAD_FORMAT = "reproit.node-http-empty-response.v1";
const UNSUPPORTED_EVIDENCE = Buffer.from("node-http-unsupported-v1", "utf8");
const SUPPORTED_OPTION_NAMES = new Set(["headers", "method"]);
const SENSITIVE_HEADERS = new Set([
  "authorization", "cookie", "proxy-authorization", "set-cookie",
]);
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

export function installHttpAdapter() {
  const restores = [];
  try {
    for (const [module, protocol] of [
      [httpModule, "http:"],
      [httpsModule, "https:"],
    ]) {
      restores.push(patchFunction(module, "request", managedRequest));
      restores.push(patchFunction(module, "get", function () {
        return managedGet(this, protocol);
      }));
    }
    return combineRestores(restores);
  } catch (error) {
    combineRestores(restores)();
    throw error;
  }
}

function managedRequest() {
  markUnowned();
  return Reflect.apply(this.original, this.receiver, this.arguments);
}

function managedGet(call, requiredProtocol) {
  let request;
  try {
    request = requestValue(call.arguments, requiredProtocol);
  } catch {
    markUnowned();
    return Reflect.apply(call.original, call.receiver, call.arguments);
  }
  let dependency;
  try {
    dependency = startDependency(request.semantic);
  } catch (error) {
    throw error;
  }
  if (dependency === null) {
    return Reflect.apply(call.original, call.receiver, call.arguments);
  }
  if (dependency.action === "replay") {
    return replayRequest(request.callback, dependency.response);
  }
  let liveRequest;
  try {
    liveRequest = Reflect.apply(call.original, call.receiver, call.arguments);
  } catch (error) {
    dependency.abandon();
    throw error;
  }
  liveRequest.prependOnceListener("response", (response) => {
    markUnsupportedResponseUse(response);
    const encoded = captureResponse(response);
    if (encoded === null) {
      markUnowned();
      dependency.abandon();
      return;
    }
    if (dependency.finish(encoded) === null) markUnowned();
  });
  liveRequest.once(errorMonitor, () => {
    // Node.js uses private error prototypes that public APIs cannot reproduce exactly.
    markUnowned();
    dependency.abandon();
  });
  liveRequest.once("upgrade", () => markUnowned());
  liveRequest.once("connect", () => markUnowned());
  markUnsupportedRequestUse(liveRequest);
  return liveRequest;
}

function requestValue(arguments_, requiredProtocol) {
  if (arguments_.length < 1 || arguments_.length > 3) throw unsupported();
  const input = arguments_[0];
  if (!(typeof input === "string" || input instanceof URL)) throw unsupported();
  const options = typeof arguments_[1] === "function" || arguments_[1] === undefined
    ? null
    : arguments_[1];
  const callback = typeof arguments_[1] === "function"
    ? arguments_[1]
    : arguments_[2];
  if (callback !== undefined && typeof callback !== "function") throw unsupported();
  if (options !== null && !plainRecord(options)) throw unsupported();
  for (const name of Object.keys(options ?? {})) {
    if (!SUPPORTED_OPTION_NAMES.has(name)) throw unsupported();
  }
  if (options?.method !== undefined && options.method !== "GET") throw unsupported();
  const target = new URL(input);
  if (target.protocol !== requiredProtocol || target.username !== "" || target.password !== "") {
    throw unsupported();
  }
  if (Buffer.byteLength(target.href) > MAX_TARGET_BYTES) throw unsupported();
  const metadata = requestHeaders(options?.headers);
  const payload = canonicalBytes({
    body: "",
    body_kind: "none",
    format: PAYLOAD_FORMAT,
    method: "GET",
    protocol: requiredProtocol.slice(0, -1),
    target: target.href,
  });
  if (payload.length > MAX_BODY_BYTES) throw unsupported();
  return {
    callback,
    semantic: dependencyRequest({
      encoding: "node-http-v1",
      metadata,
      method: "GET",
      observationClass: "outbound-http",
      operation: "outbound-http-request",
      payload,
      protocol: requiredProtocol.slice(0, -1),
      target: target.href,
    }),
  };
}

function requestHeaders(headers) {
  if (headers === undefined) return [];
  if (!plainRecord(headers)) throw unsupported();
  const metadata = [];
  let totalBytes = 0;
  for (const name of Object.keys(headers).sort()) {
    if (SENSITIVE_HEADERS.has(name.toLowerCase())) throw unsupported();
    const values = Array.isArray(headers[name]) ? headers[name] : [headers[name]];
    for (const value of values) {
      if (typeof value !== "string" && typeof value !== "number") throw unsupported();
      const bytes = Buffer.from(String(value), "utf8");
      totalBytes += Buffer.byteLength(name) + bytes.length;
      if (metadata.length >= MAX_HEADER_FIELDS || totalBytes > MAX_HEADER_BYTES) {
        throw unsupported();
      }
      metadata.push({ name, value: bytes });
    }
  }
  return metadata;
}

function captureResponse(response) {
  if (
    response === null ||
    (response.statusCode !== 204 && response.statusCode !== 304) ||
    typeof response.statusMessage !== "string" ||
    typeof response.httpVersion !== "string" ||
    response.headers?.trailer !== undefined ||
    response.headers?.["transfer-encoding"] !== undefined ||
    !emptyContentLength(response.headers?.["content-length"])
  ) {
    return null;
  }
  let metadata;
  try {
    metadata = rawHeaders(response.rawHeaders);
  } catch {
    return null;
  }
  const payload = canonicalBytes({
    format: PAYLOAD_FORMAT,
    http_version: response.httpVersion,
    status_code: response.statusCode,
    status_message: response.statusMessage,
  });
  return dependencyResponse({
    metadata,
    outcome: "response",
    payload,
    statusCode: response.statusCode,
  });
}

function replayRequest(callback, response) {
  const request = new EventEmitter();
  Object.assign(request, {
    aborted: false,
    destroyed: false,
    finished: true,
    writableEnded: true,
  });
  Object.setPrototypeOf(request, httpModule.ClientRequest.prototype);
  request.abort = request.destroy = request.end = () => {
    markUnowned();
    return request;
  };
  request.setHeader = request.removeHeader = request.write = () => {
    markUnowned();
    throw replayInvalid();
  };
  markUnsupportedRequestUse(request);
  if (typeof callback === "function") request.once("response", callback);
  let event;
  let value;
  try {
    if (response.outcome === "response") {
      event = "response";
      value = replayResponse(response);
    } else {
      throw replayInvalid();
    }
  } catch (error) {
    event = "error";
    value = error;
  }
  process.nextTick(() => {
    request.emit(event, value);
  });
  return request;
}

function replayResponse(response) {
  const payload = parsePayload(response.payload, [
    "format", "http_version", "status_code", "status_message",
  ]);
  if (
    response.statusCode !== payload.status_code ||
    (payload.status_code !== 204 && payload.status_code !== 304) ||
    typeof payload.http_version !== "string" ||
    typeof payload.status_message !== "string"
  ) {
    throw replayInvalid();
  }
  const raw = [];
  const headers = Object.create(null);
  let totalBytes = 0;
  if (!Array.isArray(response.metadata) || response.metadata.length > MAX_HEADER_FIELDS) {
    throw replayInvalid();
  }
  for (const field of response.metadata) {
    const name = field.name;
    if (typeof name !== "string" || !Buffer.isBuffer(field.value)) {
      throw replayInvalid();
    }
    let value;
    try {
      value = STRICT_UTF8.decode(field.value);
    } catch {
      throw replayInvalid();
    }
    totalBytes += Buffer.byteLength(name) + field.value.length;
    if (totalBytes > MAX_HEADER_BYTES || SENSITIVE_HEADERS.has(name.toLowerCase())) {
      throw replayInvalid();
    }
    raw.push(name, value);
    const lower = name.toLowerCase();
    headers[lower] = headers[lower] === undefined ? value : `${headers[lower]}, ${value}`;
  }
  const stream = Readable.from([]);
  Object.assign(stream, {
    complete: true,
    headers,
    httpVersion: payload.http_version,
    rawHeaders: raw,
    rawTrailers: [],
    statusCode: payload.status_code,
    statusMessage: payload.status_message,
    trailers: Object.create(null),
  });
  Object.setPrototypeOf(stream, httpModule.IncomingMessage.prototype);
  markUnsupportedResponseUse(stream);
  return stream;
}

function parsePayload(bytes, keys) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_BODY_BYTES) throw replayInvalid();
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
    if (!bytes.equals(canonicalBytes(value))) throw replayInvalid();
  } catch {
    throw replayInvalid();
  }
  if (!plainRecord(value) || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0") ||
      value.format !== PAYLOAD_FORMAT) {
    throw replayInvalid();
  }
  return value;
}

function rawHeaders(values) {
  if (!Array.isArray(values) || values.length % 2 !== 0) throw unsupported();
  const metadata = [];
  let totalBytes = 0;
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (typeof name !== "string" || typeof value !== "string" ||
        SENSITIVE_HEADERS.has(name.toLowerCase())) {
      throw unsupported();
    }
    totalBytes += Buffer.byteLength(name) + Buffer.byteLength(value);
    if (metadata.length >= MAX_HEADER_FIELDS || totalBytes > MAX_HEADER_BYTES) {
      throw unsupported();
    }
    metadata.push({ name, value: Buffer.from(value, "utf8") });
  }
  return metadata;
}

function emptyContentLength(value) {
  return value === undefined || value === "0";
}

function markUnsupportedRequestUse(request) {
  patchInstanceMethods(request, [
    "abort", "destroy", "end", "flushHeaders", "removeHeader", "setHeader",
    "setTimeout", "write",
  ]);
  patchInstanceEvents(request, new Set([
    "connect", "continue", "finish", "information", "socket", "timeout", "upgrade",
  ]));
}

function markUnsupportedResponseUse(response) {
  patchInstanceMethods(response, ["pipe", "read", "resume", "setEncoding"]);
  patchInstanceEvents(response, new Set(["aborted", "data", "end", "readable"]));
}

function patchInstanceMethods(owner, names) {
  for (const name of names) {
    const original = owner[name];
    if (typeof original !== "function") continue;
    try {
      owner[name] = function (...arguments_) {
        markUnowned();
        return Reflect.apply(original, this, arguments_);
      };
    } catch {
      markUnowned();
    }
  }
}

function patchInstanceEvents(owner, unsupportedEvents) {
  for (const name of ["addListener", "on", "once", "prependListener", "prependOnceListener"]) {
    const original = owner[name];
    if (typeof original !== "function") continue;
    try {
      owner[name] = function (event, ...arguments_) {
        if (unsupportedEvents.has(event)) markUnowned();
        return Reflect.apply(original, this, [event, ...arguments_]);
      };
    } catch {
      markUnowned();
    }
  }
}

function patchFunction(owner, name, implementation) {
  const descriptor = Object.getOwnPropertyDescriptor(owner, name);
  if (descriptor === undefined || typeof descriptor.value !== "function") {
    throw new Error("The Node.js HTTP hook is unavailable.");
  }
  const original = descriptor.value;
  const replacement = function (...arguments_) {
    return Reflect.apply(implementation, {
      arguments: arguments_, original, receiver: this,
    }, arguments_);
  };
  Object.defineProperty(owner, name, { ...descriptor, value: replacement });
  return () => {
    const current = Object.getOwnPropertyDescriptor(owner, name);
    if (current?.value === replacement) Object.defineProperty(owner, name, descriptor);
  };
}

function combineRestores(restores) {
  return () => {
    for (let index = restores.length - 1; index >= 0; index -= 1) restores[index]();
  };
}

function plainRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function markUnowned() {
  const context = currentOperationContext();
  if (context !== null) {
    markOperationUnowned(context, "outbound-http", UNSUPPORTED_EVIDENCE);
  }
}

function unsupported() {
  return new TypeError("The Node.js HTTP operation is unsupported.");
}

function replayInvalid() {
  const error = new Error("The recorded Node.js HTTP dependency is invalid.");
  error.code = "ERR_REPROIT_HTTP_REPLAY";
  return error;
}
