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
const MAX_PAYLOAD_BYTES = 2 * MAX_BODY_BYTES;
const MAX_RESPONSE_STREAMS = 512;
const MAX_TARGET_BYTES = 8 * 1_024;
const EMPTY_PAYLOAD_FORMAT = "reproit.node-http-empty-response.v1";
const STREAM_PAYLOAD_FORMAT = "reproit.node-http-response.v1";
const UNSUPPORTED_EVIDENCE = Buffer.from("node-http-unsupported-v1", "utf8");
const SUPPORTED_OPTION_NAMES = new Set(["headers", "method"]);
const SENSITIVE_HEADERS = new Set([
  "authorization", "cookie", "proxy-authenticate", "proxy-authorization",
  "set-cookie", "www-authenticate",
]);
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });
let activeResponseStreams = 0;

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
    let empty;
    try {
      empty = captureEmptyResponse(response);
    } catch {
      markUnowned();
      dependency.abandon();
      return;
    }
    if (empty !== null) {
      markUnsupportedResponseUse(response);
      if (dependency.finish(empty) === null) markUnowned();
      return;
    }
    if (!captureResponseStream(response, dependency)) {
      markUnowned();
      dependency.abandon();
    }
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
    format: EMPTY_PAYLOAD_FORMAT,
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

function captureEmptyResponse(response) {
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
    format: EMPTY_PAYLOAD_FORMAT,
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

function captureResponseStream(response, dependency) {
  let head;
  try {
    head = responseHead(response);
  } catch {
    return false;
  }
  if (head === null || activeResponseStreams >= MAX_RESPONSE_STREAMS) return false;
  const pushDescriptor = Object.getOwnPropertyDescriptor(response, "push");
  const originalPush = response.push;
  if (typeof originalPush !== "function") return false;
  const state = {
    body: [], bytes: 0, dependency, head, response, terminal: false,
  };
  const replacement = function (chunk, ...arguments_) {
    let result;
    try {
      result = Reflect.apply(originalPush, this, [chunk, ...arguments_]);
    } catch (error) {
      failResponseStream(state);
      throw error;
    }
    if (chunk === null) finishResponseStream(state);
    else captureResponseChunk(state, chunk, arguments_[0]);
    return result;
  };
  try {
    Object.defineProperty(response, "push", {
      configurable: true,
      value: replacement,
      writable: true,
    });
  } catch {
    return false;
  }
  state.pushDescriptor = pushDescriptor;
  state.replacement = replacement;
  activeResponseStreams += 1;
  try {
    response.once(errorMonitor, () => failResponseStream(state));
    response.once("aborted", () => failResponseStream(state));
    response.once("close", () => failResponseStream(state));
    markUnsupportedResponseUse(response);
  } catch {
    failResponseStream(state);
    return true;
  }
  return true;
}

function responseHead(response) {
  if (
    response === null ||
    !Number.isInteger(response.statusCode) ||
    response.statusCode < 100 ||
    response.statusCode > 599 ||
    response.statusCode === 101 ||
    typeof response.statusMessage !== "string" ||
    typeof response.httpVersion !== "string" ||
    !boundedContentLength(response.headers?.["content-length"])
  ) {
    return null;
  }
  let metadata;
  try {
    metadata = rawHeaders(response.rawHeaders);
  } catch {
    return null;
  }
  return { metadata };
}

function boundedContentLength(value) {
  if (value === undefined) return true;
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/u.test(value)) return false;
  const length = Number(value);
  return Number.isSafeInteger(length) && length <= MAX_BODY_BYTES;
}

function captureResponseChunk(state, chunk, encoding) {
  if (state.terminal) return;
  let bytes;
  try {
    if (chunk instanceof Uint8Array) bytes = Buffer.from(chunk);
    else if (typeof chunk === "string") bytes = Buffer.from(chunk, encoding);
    else throw unsupported();
  } catch {
    failResponseStream(state);
    return;
  }
  if (bytes.length > MAX_BODY_BYTES - state.bytes) {
    failResponseStream(state);
    return;
  }
  state.bytes += bytes.length;
  state.body.push(bytes);
}

function finishResponseStream(state) {
  if (state.terminal) return;
  state.terminal = true;
  activeResponseStreams -= 1;
  restoreResponsePush(state);
  let encoded;
  try {
    encoded = captureStreamResponse(state.response, state.head, Buffer.concat(state.body));
  } catch {
    encoded = null;
  }
  if (encoded === null) {
    markUnowned();
    state.dependency.abandon();
    return;
  }
  if (state.dependency.finish(encoded) === null) markUnowned();
}

function failResponseStream(state) {
  if (state.terminal) return;
  state.terminal = true;
  activeResponseStreams -= 1;
  restoreResponsePush(state);
  markUnowned();
  state.dependency.abandon();
}

function restoreResponsePush(state) {
  try {
    if (Object.getOwnPropertyDescriptor(state.response, "push")?.value !== state.replacement) {
      return;
    }
    if (state.pushDescriptor === undefined) delete state.response.push;
    else Object.defineProperty(state.response, "push", state.pushDescriptor);
  } catch {
    markUnowned();
  }
}

function captureStreamResponse(response, head, body) {
  const declaredLength = response.headers?.["content-length"];
  if (response.complete !== true ||
      (declaredLength !== undefined && Number(declaredLength) !== body.length)) {
    return null;
  }
  let rawTrailers;
  try {
    rawHeaders(response.rawTrailers);
    rawTrailers = [...response.rawTrailers];
  } catch {
    return null;
  }
  const payload = canonicalBytes({
    body: body.toString("base64url"),
    format: STREAM_PAYLOAD_FORMAT,
    http_version: response.httpVersion,
    raw_trailers: rawTrailers,
    status_code: response.statusCode,
    status_message: response.statusMessage,
  });
  if (payload.length > MAX_PAYLOAD_BYTES) return null;
  return dependencyResponse({
    metadata: head.metadata,
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
  const payload = parsePayload(response.payload);
  const empty = payload.format === EMPTY_PAYLOAD_FORMAT;
  const streamResponse = payload.format === STREAM_PAYLOAD_FORMAT;
  if (
    (!empty && !streamResponse) ||
    (empty && !exactKeys(payload, [
      "format", "http_version", "status_code", "status_message",
    ])) ||
    (streamResponse && !exactKeys(payload, [
      "body", "format", "http_version", "raw_trailers", "status_code", "status_message",
    ])) ||
    response.statusCode !== payload.status_code ||
    (empty && payload.status_code !== 204 && payload.status_code !== 304) ||
    !Number.isInteger(payload.status_code) ||
    payload.status_code < 100 ||
    payload.status_code > 599 ||
    payload.status_code === 101 ||
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
  let body = Buffer.alloc(0);
  let rawTrailers = [];
  if (streamResponse) {
    body = decodeBody(payload.body);
    rawHeaders(payload.raw_trailers);
    rawTrailers = [...payload.raw_trailers];
  }
  const trailers = headerObject(rawTrailers);
  const stream = Readable.from(body.length === 0 ? [] : [body]);
  Object.assign(stream, {
    complete: true,
    headers,
    httpVersion: payload.http_version,
    rawHeaders: raw,
    rawTrailers,
    statusCode: payload.status_code,
    statusMessage: payload.status_message,
    trailers,
  });
  Object.setPrototypeOf(stream, httpModule.IncomingMessage.prototype);
  markUnsupportedResponseUse(stream);
  return stream;
}

function parsePayload(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_PAYLOAD_BYTES) throw replayInvalid();
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
    if (!bytes.equals(canonicalBytes(value))) throw replayInvalid();
  } catch {
    throw replayInvalid();
  }
  if (!plainRecord(value)) {
    throw replayInvalid();
  }
  return value;
}

function exactKeys(value, keys) {
  return Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function decodeBody(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value)) throw replayInvalid();
  const body = Buffer.from(value, "base64url");
  if (body.length > MAX_BODY_BYTES || body.toString("base64url") !== value) {
    throw replayInvalid();
  }
  return body;
}

function headerObject(raw) {
  const headers = Object.create(null);
  for (let index = 0; index < raw.length; index += 2) {
    const lower = raw[index].toLowerCase();
    const value = raw[index + 1];
    headers[lower] = headers[lower] === undefined ? value : `${headers[lower]}, ${value}`;
  }
  return headers;
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
    "connect", "continue", "information", "socket", "timeout", "upgrade",
  ]));
}

function markUnsupportedResponseUse(response) {
  patchInstanceMethods(response, ["setTimeout"]);
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
