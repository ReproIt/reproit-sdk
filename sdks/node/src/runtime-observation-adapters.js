import { createRequire, syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  currentOperationContext,
  markOperationUnowned,
} from "./engine-operation.js";
import {
  installObservationAdapter,
  removeObservationAdapter,
} from "./observation-adapters.js";
import {
  encodedTarget,
  replayValue,
  responseBytes,
  semanticRequest,
  SEMANTIC_OPERATIONS,
  startSemanticObservation,
} from "./semantic-observation.js";

const require = createRequire(import.meta.url);
const cryptoModule = require("node:crypto");
const fsModule = require("node:fs");
const fsPromises = require("node:fs/promises");
const originalCreateHash = cryptoModule.createHash;
const implementationDigest = runtimeImplementationDigest();
const MAX_VALUE_BYTES = 32 * 1_024;
const UNSUPPORTED_EVIDENCE = Buffer.from("node-runtime-unsupported-v1", "utf8");
const CLASSES = ["clock", "environment", "filesystem", "randomness"];
const installedClasses = [];
let leaseCount = 0;

export function acquireRuntimeObservationAdapters() {
  if (leaseCount === 0) installRuntimeObservationAdapters();
  leaseCount += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    leaseCount -= 1;
    if (leaseCount === 0) restoreRuntimeObservationAdapters();
  };
}

export function runtimeObservationAdapterStateForTest() {
  return Object.freeze({
    classes: installedClasses.map((entry) => entry.registration.class),
    leases: leaseCount,
  });
}

function installRuntimeObservationAdapters() {
  const installers = {
    clock: installClockAdapter,
    environment: installEnvironmentAdapter,
    filesystem: installFilesystemAdapter,
    randomness: installRandomnessAdapter,
  };
  for (const observationClass of CLASSES) {
    let registration;
    let restore;
    try {
      registration = registrationFor(observationClass);
      restore = installers[observationClass]();
      installObservationAdapter(registration);
      installedClasses.push({ registration, restore });
    } catch {
      try {
        restore?.();
      } catch {
        // A hook failure must not change application behavior.
      }
    }
  }
  try {
    syncBuiltinESMExports();
  } catch {
    restoreRuntimeObservationAdapters();
  }
}

function restoreRuntimeObservationAdapters() {
  while (installedClasses.length > 0) {
    const installed = installedClasses.pop();
    try {
      installed.restore();
    } catch {
      // A restore failure must not change application behavior.
    }
    removeObservationAdapter(installed.registration);
  }
  try {
    syncBuiltinESMExports();
  } catch {
    // A restore failure must not change application behavior.
  }
}

function registrationFor(observationClass) {
  if (implementationDigest === null) {
    throw new Error("The Node.js runtime adapter identity is unavailable.");
  }
  return Object.freeze({
    adapter_id: `node-runtime-${observationClass}`,
    adapter_version: "1.0.0",
    class: observationClass,
    implementation_digest: implementationDigest,
  });
}

function runtimeImplementationDigest() {
  const files = [
    fileURLToPath(import.meta.url),
    fileURLToPath(new URL("./semantic-observation.js", import.meta.url)),
  ];
  const hash = originalCreateHash("sha256");
  try {
    for (const file of files) {
      const bytes = fsModule.readFileSync(file);
      hash.update(Buffer.from(path.basename(file), "utf8"));
      hash.update(Buffer.from([0]));
      hash.update(bytes);
    }
  } catch {
    return null;
  }
  return `sha256:${hash.digest("hex")}`;
}

function installClockAdapter() {
  const originalDate = globalThis.Date;
  const restores = [];
  try {
    const managedDate = function Date(...arguments_) {
      if (new.target !== undefined) {
        if (arguments_.length > 0) {
          return Reflect.construct(originalDate, arguments_, new.target);
        }
        return Reflect.construct(originalDate, [observedWallTime(originalDate)], new.target);
      }
      return new originalDate(observedWallTime(originalDate)).toString();
    };
    Object.setPrototypeOf(managedDate, originalDate);
    managedDate.prototype = originalDate.prototype;
    Object.defineProperty(managedDate, "name", { configurable: true, value: "Date" });
    Object.defineProperty(managedDate, "length", { configurable: true, value: 7 });
    managedDate.now = () => observedWallTime(originalDate);
    restores.push(patchValue(globalThis, "Date", managedDate));
    const performancePrototype = Object.getPrototypeOf(globalThis.performance);
    for (const name of [
      "eventLoopUtilization", "mark", "measure", "now", "toJSON",
    ]) {
      restores.push(patchUnownedFunction(performancePrototype, name, "clock"));
    }
    restores.push(patchUnownedAccessor(performancePrototype, "timeOrigin", "clock"));
    for (const name of ["cpuUsage", "resourceUsage", "uptime"]) {
      restores.push(patchUnownedFunction(process, name, "clock"));
    }
    restores.push(patchUnownedFunction(process, "hrtime", "clock"));
    restores.push(patchUnownedFunction(process.hrtime, "bigint", "clock"));
    const dateTimeFormatPrototype = Intl.DateTimeFormat.prototype;
    restores.push(patchUnownedAccessor(dateTimeFormatPrototype, "format", "clock", true));
    restores.push(patchUnownedFunction(dateTimeFormatPrototype, "formatToParts", "clock"));
    return combineRestores(restores);
  } catch (error) {
    combineRestores(restores)();
    throw error;
  }
}

function observedWallTime(date) {
  const request = semanticRequest(
    SEMANTIC_OPERATIONS.clock,
    null,
    null,
    null,
  );
  return observeSync(
    "clock",
    request,
    () => date.now(),
    (milliseconds) => {
      const bytes = Buffer.alloc(8);
      bytes.writeBigInt64BE(BigInt(milliseconds) * 1_000_000n);
      return bytes;
    },
    (bytes) => Number(bytes.readBigInt64BE()) / 1_000_000,
  );
}

function installEnvironmentAdapter() {
  const descriptor = Object.getOwnPropertyDescriptor(process, "env");
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new Error("The process environment hook is unavailable.");
  }
  const environment = descriptor.value;
  const unownedContexts = new WeakSet();
  const proxy = new Proxy(environment, {
    defineProperty(target, property, value) {
      markUnowned("environment", unownedContexts);
      return Reflect.defineProperty(target, property, value);
    },
    deleteProperty(target, property) {
      markUnowned("environment", unownedContexts);
      return Reflect.deleteProperty(target, property);
    },
    get(target, property, receiver) {
      if (
        typeof property !== "string" ||
        property in Object.prototype ||
        contextIsUnowned(unownedContexts)
      ) {
        return Reflect.get(target, property, receiver);
      }
      return observedEnvironmentValue(target, property);
    },
    getOwnPropertyDescriptor(target, property) {
      markUnowned("environment", unownedContexts);
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
    has(target, property) {
      if (typeof property !== "string" || property in Object.prototype) {
        return Reflect.has(target, property);
      }
      if (contextIsUnowned(unownedContexts)) return Reflect.has(target, property);
      return observedEnvironmentValue(target, property) !== undefined;
    },
    ownKeys(target) {
      markUnowned("environment", unownedContexts);
      return Reflect.ownKeys(target);
    },
    set(target, property, value, receiver) {
      markUnowned("environment", unownedContexts);
      return Reflect.set(target, property, value, receiver);
    },
  });
  Object.defineProperty(process, "env", { ...descriptor, value: proxy });
  return () => {
    const current = Object.getOwnPropertyDescriptor(process, "env");
    if (current?.value === proxy) Object.defineProperty(process, "env", descriptor);
  };
}

function observedEnvironmentValue(environment, name) {
  const target = encodedTarget(name);
  if (target === null) {
    markUnowned("environment");
    return Reflect.get(environment, name);
  }
  const request = semanticRequest(
    SEMANTIC_OPERATIONS.environment,
    target,
    null,
    null,
  );
  return observeSync(
    "environment",
    request,
    () => Reflect.get(environment, name),
    (value) => value === undefined ? null : responseBytes(Buffer.from(value, "utf8")),
    (bytes) => bytes === null ? undefined : bytes.toString("utf8"),
  );
}

function installFilesystemAdapter() {
  const restores = [];
  try {
    restores.push(patchFunction(fsModule, "readFileSync", managedReadFileSync));
    restores.push(patchFunction(fsModule, "readFile", managedReadFile));
    restores.push(patchFunction(fsPromises, "readFile", managedPromiseReadFile));
    for (const name of [
      "access", "accessSync", "createReadStream", "fstat", "fstatSync", "lstat",
      "lstatSync", "open", "openSync", "opendir", "opendirSync", "read", "readdir",
      "readdirSync", "readlink", "readlinkSync", "readSync", "readv", "readvSync",
      "realpath", "realpathSync", "stat", "statSync", "statfs", "statfsSync",
    ]) {
      restores.push(patchUnownedFunction(fsModule, name, "filesystem"));
    }
    for (const name of [
      "access", "lstat", "open", "opendir", "readdir", "readlink", "realpath", "stat",
      "statfs",
    ]) {
      restores.push(patchUnownedFunction(fsPromises, name, "filesystem"));
    }
    return combineRestores(restores);
  } catch (error) {
    combineRestores(restores)();
    throw error;
  }
}

function managedReadFileSync(file, options) {
  const request = filesystemRequest(file, options);
  if (request === null) {
    markUnowned("filesystem");
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  return observeSync(
    "filesystem",
    request,
    () => Reflect.apply(this.original, this.receiver, this.arguments),
    responseBytes,
    (bytes) => Buffer.from(bytes),
  );
}

function managedReadFile(file, options, callback) {
  const normalized = normalizeReadFileCallback(options, callback);
  if (normalized === null) {
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  const request = filesystemRequest(file, normalized.options);
  if (request === null) {
    markUnowned("filesystem");
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  const observation = startSemanticObservation("filesystem", request);
  if (observation === null) {
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  if (observation.action === "replay") {
    setImmediate(() => deliverReplayCallback(normalized.callback, observation.response));
    return undefined;
  }
  const wrapped = (error, value) => {
    if (error !== null) observation.finishError(error);
    else finishCapturedValue(observation, value);
    Reflect.apply(normalized.callback, undefined, [error, value]);
  };
  const arguments_ = normalized.options === undefined
    ? [file, wrapped]
    : [file, normalized.options, wrapped];
  return Reflect.apply(this.original, this.receiver, arguments_);
}

function managedPromiseReadFile(file, options) {
  const request = filesystemRequest(file, options);
  if (request === null) {
    markUnowned("filesystem");
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  return observePromise(
    "filesystem",
    request,
    () => Reflect.apply(this.original, this.receiver, this.arguments),
    responseBytes,
    (bytes) => Buffer.from(bytes),
  );
}

function filesystemRequest(file, options) {
  if (typeof file !== "string" || !returnsBuffer(options)) return null;
  const target = encodedTarget(path.resolve(file));
  if (target === null) return null;
  return semanticRequest(
    SEMANTIC_OPERATIONS.filesystem,
    target,
    0,
    MAX_VALUE_BYTES,
  );
}

function returnsBuffer(options) {
  if (options === undefined || options === null) return true;
  return typeof options === "object" &&
    (options.encoding === undefined || options.encoding === null);
}

function normalizeReadFileCallback(options, callback) {
  if (typeof options === "function" && callback === undefined) {
    return { callback: options, options: undefined };
  }
  return typeof callback === "function" ? { callback, options } : null;
}

function installRandomnessAdapter() {
  const restores = [];
  try {
    restores.push(patchFunction(Math, "random", managedMathRandom));
    restores.push(patchFunction(cryptoModule, "randomBytes", managedRandomBytes));
    restores.push(patchFunction(cryptoModule, "randomFillSync", managedRandomFillSync));
    restores.push(patchFunction(cryptoModule, "randomFill", managedRandomFill));
    restores.push(patchFunction(cryptoModule, "randomUUID", managedRandomUUID));
    for (const name of [
      "generateKey", "generateKeyPair", "generateKeyPairSync", "generateKeySync",
      "generatePrime", "generatePrimeSync", "pseudoRandomBytes", "randomInt",
    ]) {
      restores.push(patchUnownedFunction(cryptoModule, name, "randomness"));
    }
    const cryptoPrototype = Object.getPrototypeOf(cryptoModule.webcrypto);
    restores.push(patchFunction(cryptoPrototype, "getRandomValues", managedGetRandomValues));
    restores.push(patchUnownedFunction(
      Object.getPrototypeOf(cryptoModule.webcrypto.subtle),
      "generateKey",
      "randomness",
    ));
    return combineRestores(restores);
  } catch (error) {
    combineRestores(restores)();
    throw error;
  }
}

function managedMathRandom() {
  return observeSync(
    "randomness",
    randomRequest(8),
    () => Reflect.apply(this.original, this.receiver, this.arguments),
    (value) => {
      const bytes = Buffer.alloc(8);
      bytes.writeDoubleBE(value);
      return bytes;
    },
    (bytes) => bytes.readDoubleBE(),
  );
}

function managedRandomBytes(size, callback) {
  if (!validRandomLength(size)) {
    markUnowned("randomness");
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  const request = randomRequest(size);
  if (callback === undefined) {
    return observeSync(
      "randomness",
      request,
      () => Reflect.apply(this.original, this.receiver, this.arguments),
      responseBytes,
      (bytes) => Buffer.from(bytes),
    );
  }
  if (typeof callback !== "function") {
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  const observation = startSemanticObservation("randomness", request);
  if (observation === null) {
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  if (observation.action === "replay") {
    setImmediate(() => deliverReplayCallback(callback, observation.response));
    return undefined;
  }
  return Reflect.apply(this.original, this.receiver, [size, (error, value) => {
    if (error !== null) observation.finishError(error);
    else finishCapturedValue(observation, value);
    Reflect.apply(callback, undefined, [error, value]);
  }]);
}

function managedRandomFillSync(buffer, offset, size) {
  const region = randomFillRegion(buffer, offset, size);
  if (region === null) {
    markUnowned("randomness");
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  return observeSync(
    "randomness",
    randomRequest(region.length),
    () => Reflect.apply(this.original, this.receiver, this.arguments),
    () => Buffer.from(region.bytes()),
    (bytes) => {
      region.write(bytes);
      return buffer;
    },
  );
}

function managedRandomFill(buffer, offset, size, callback) {
  const normalized = normalizeRandomFill(buffer, offset, size, callback);
  if (normalized === null) {
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  const region = randomFillRegion(buffer, normalized.offset, normalized.size);
  if (region === null) {
    markUnowned("randomness");
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  const observation = startSemanticObservation("randomness", randomRequest(region.length));
  if (observation === null) {
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  if (observation.action === "replay") {
    setImmediate(() => {
      try {
        region.write(replayValue(observation.response));
        Reflect.apply(normalized.callback, undefined, [null, buffer]);
      } catch (error) {
        Reflect.apply(normalized.callback, undefined, [error]);
      }
    });
    return undefined;
  }
  const arguments_ = randomFillArguments(buffer, normalized, (error, value) => {
    if (error !== null) observation.finishError(error);
    else observation.finishResponse(Buffer.from(region.bytes()));
    Reflect.apply(normalized.callback, undefined, [error, value]);
  });
  return Reflect.apply(this.original, this.receiver, arguments_);
}

function managedRandomUUID() {
  return observeSync(
    "randomness",
    randomRequest(36),
    () => Reflect.apply(this.original, this.receiver, this.arguments),
    (value) => responseBytes(Buffer.from(value, "utf8")),
    (bytes) => bytes.toString("utf8"),
  );
}

function managedGetRandomValues(array) {
  const region = randomFillRegion(array, 0, array?.byteLength);
  if (region === null) {
    markUnowned("randomness");
    return Reflect.apply(this.original, this.receiver, this.arguments);
  }
  return observeSync(
    "randomness",
    randomRequest(region.length),
    () => Reflect.apply(this.original, this.receiver, this.arguments),
    () => Buffer.from(region.bytes()),
    (bytes) => {
      region.write(bytes);
      return array;
    },
  );
}

function randomRequest(length) {
  return semanticRequest(
    SEMANTIC_OPERATIONS.randomness,
    null,
    null,
    length,
  );
}

function randomFillRegion(value, offset = 0, size = undefined) {
  let bytes;
  if (ArrayBuffer.isView(value)) {
    bytes = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  } else if (value instanceof ArrayBuffer) {
    bytes = Buffer.from(value);
  } else {
    return null;
  }
  const length = size === undefined ? bytes.length - offset : size;
  if (
    !Number.isInteger(offset) ||
    !validRandomLength(length) ||
    offset < 0 ||
    offset + length > bytes.length
  ) {
    return null;
  }
  return {
    bytes: () => bytes.subarray(offset, offset + length),
    length,
    write: (valueBytes) => valueBytes.copy(bytes, offset),
  };
}

function normalizeRandomFill(buffer, offset, size, callback) {
  if (typeof offset === "function" && size === undefined && callback === undefined) {
    return { callback: offset, offset: 0, size: undefined };
  }
  if (typeof size === "function" && callback === undefined) {
    return { callback: size, offset, size: undefined };
  }
  return typeof callback === "function" ? { callback, offset, size } : null;
}

function randomFillArguments(buffer, normalized, callback) {
  if (normalized.size !== undefined) {
    return [buffer, normalized.offset, normalized.size, callback];
  }
  if (normalized.offset !== 0) return [buffer, normalized.offset, callback];
  return [buffer, callback];
}

function validRandomLength(value) {
  return Number.isInteger(value) && value > 0 && value <= MAX_VALUE_BYTES;
}

function observeSync(observationClass, request, live, encode, decode) {
  const observation = startSemanticObservation(observationClass, request);
  if (observation === null) return live();
  if (observation.action === "replay") {
    return decode(replayValue(observation.response));
  }
  let result;
  try {
    result = live();
  } catch (error) {
    observation.finishError(error);
    throw error;
  }
  let bytes;
  try {
    bytes = encode(result);
  } catch {
    observation.abandon();
    return result;
  }
  if (bytes === null) observation.abandon();
  else observation.finishResponse(bytes);
  return result;
}

function observePromise(observationClass, request, live, encode, decode) {
  const observation = startSemanticObservation(observationClass, request);
  if (observation === null) return live();
  if (observation.action === "replay") {
    try {
      return Promise.resolve(decode(replayValue(observation.response)));
    } catch (error) {
      return Promise.reject(error);
    }
  }
  let promise;
  try {
    promise = live();
  } catch (error) {
    observation.finishError(error);
    throw error;
  }
  return Promise.resolve(promise).then(
    (value) => {
      finishCapturedValue(observation, value, encode);
      return value;
    },
    (error) => {
      observation.finishError(error);
      throw error;
    },
  );
}

function finishCapturedValue(observation, value, encode = responseBytes) {
  let bytes;
  try {
    bytes = encode(value);
  } catch {
    observation.abandon();
    return;
  }
  if (bytes === null) observation.abandon();
  else observation.finishResponse(bytes);
}

function deliverReplayCallback(callback, response) {
  try {
    const value = replayValue(response);
    Reflect.apply(callback, undefined, [null, Buffer.from(value)]);
  } catch (error) {
    Reflect.apply(callback, undefined, [error]);
  }
}

function patchFunction(owner, name, implementation) {
  const original = owner?.[name];
  if (typeof original !== "function") {
    throw new Error("The Node.js runtime hook is unavailable.");
  }
  const replacement = function (...arguments_) {
    return Reflect.apply(implementation, {
      arguments: arguments_,
      original,
      receiver: this,
    }, arguments_);
  };
  copyFunctionProperties(original, replacement);
  return patchValue(owner, name, replacement);
}

function patchUnownedFunction(owner, name, observationClass) {
  const original = owner?.[name];
  if (typeof original !== "function") return () => {};
  return patchFunction(owner, name, function () {
    markUnowned(observationClass);
    return Reflect.apply(this.original, this.receiver, this.arguments);
  });
}

function patchValue(owner, name, replacement) {
  const descriptor = Object.getOwnPropertyDescriptor(owner, name);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new Error("The Node.js runtime hook is unavailable.");
  }
  Object.defineProperty(owner, name, { ...descriptor, value: replacement });
  return () => {
    const current = Object.getOwnPropertyDescriptor(owner, name);
    if (current?.value === replacement) Object.defineProperty(owner, name, descriptor);
  };
}

function patchUnownedAccessor(owner, name, observationClass, wrapFunction = false) {
  const descriptor = Object.getOwnPropertyDescriptor(owner, name);
  if (descriptor === undefined || typeof descriptor.get !== "function") {
    return () => {};
  }
  const originalGet = descriptor.get;
  const replacementGet = function () {
    const value = Reflect.apply(originalGet, this, []);
    if (!wrapFunction || typeof value !== "function") {
      markUnowned(observationClass);
      return value;
    }
    return function (...arguments_) {
      markUnowned(observationClass);
      return Reflect.apply(value, this, arguments_);
    };
  };
  Object.defineProperty(owner, name, { ...descriptor, get: replacementGet });
  return () => {
    const current = Object.getOwnPropertyDescriptor(owner, name);
    if (current?.get === replacementGet) Object.defineProperty(owner, name, descriptor);
  };
}

function copyFunctionProperties(original, replacement) {
  for (const [name, descriptor] of Object.entries(
    Object.getOwnPropertyDescriptors(original),
  )) {
    if (["arguments", "caller", "length", "name", "prototype"].includes(name)) continue;
    try {
      Object.defineProperty(replacement, name, descriptor);
    } catch {
      // A function property must not block the runtime hook.
    }
  }
}

function combineRestores(restores) {
  return () => {
    for (let index = restores.length - 1; index >= 0; index -= 1) {
      restores[index]();
    }
  };
}

function markUnowned(observationClass, unownedContexts = null) {
  const context = currentOperationContext();
  if (context === null) return;
  unownedContexts?.add(context);
  markOperationUnowned(context, observationClass, UNSUPPORTED_EVIDENCE);
}

function contextIsUnowned(unownedContexts) {
  const context = currentOperationContext();
  return context !== null && unownedContexts.has(context);
}
