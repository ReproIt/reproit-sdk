import { createRequire } from "node:module";

import {
  currentOperationContext,
  markOperationUnowned,
} from "./engine-operation.js";
import {
  dependencyRequest,
  dependencyResponse,
  runDependency,
} from "./semantic-dependency.js";

const require = createRequire(import.meta.url);
const sqliteModule = require("node:sqlite");
const workerThreads = require("node:worker_threads");
const MAX_ADAPTER_PAYLOAD_BYTES = 16 * 1_024;
const MAX_BIND_ARGUMENTS = 256;
const MAX_DATABASE_IDENTITIES = 65_536;
const MAX_OBJECT_FIELDS = 256;
const MAX_RESULT_ROWS = 256;
const MAX_STATEMENTS_PER_DATABASE = 65_536;
const PAYLOAD_FORMAT = "reproit.node-sqlite.v1";
const UNSUPPORTED_EVIDENCE = Buffer.from("node-sqlite-unsupported-v1", "utf8");

export function installSqliteAdapter() {
  const databaseStates = new WeakMap();
  const statementStates = new WeakMap();
  const restores = [];
  let nextDatabaseId = 1;

  const stateForDatabase = (database) => {
    let state = databaseStates.get(database);
    if (state !== undefined) return state;
    if (nextDatabaseId > MAX_DATABASE_IDENTITIES) throw adapterLimit();
    state = {
      id: `database-${nextDatabaseId}`,
      nextStatementId: 1,
    };
    nextDatabaseId += 1;
    databaseStates.set(database, state);
    return state;
  };

  try {
    const databasePrototype = sqliteModule.DatabaseSync.prototype;
    const statementPrototype = sqliteModule.StatementSync.prototype;
    restores.push(patchMethod(databasePrototype, "exec", function (sql) {
      let request;
      try {
        const state = stateForDatabase(this.receiver);
        request = createRequest(state, "exec", null, sql, []);
      } catch {
        return unsupportedLiveCall(this.original, this.receiver, this.arguments);
      }
      return executeDependency(
        request,
        () => Reflect.apply(this.original, this.receiver, this.arguments),
        () => encodePayload([PAYLOAD_FORMAT, "exec"]),
        (payload) => {
          requirePayload(payload, "exec", 2);
          return undefined;
        },
      );
    }));
    restores.push(patchMethod(databasePrototype, "prepare", function (sql) {
      let databaseState;
      let statementId;
      let request;
      try {
        databaseState = stateForDatabase(this.receiver);
        statementId = allocateStatementId(databaseState);
        request = createRequest(
          databaseState,
          "prepare",
          statementId,
          sql,
          [],
        );
      } catch {
        return unsupportedLiveCall(this.original, this.receiver, this.arguments);
      }
      const state = {
        database: databaseState,
        id: statementId,
        sql,
        surrogate: false,
      };
      return executeDependency(
        request,
        () => {
          const statement = Reflect.apply(
            this.original,
            this.receiver,
            this.arguments,
          );
          statementStates.set(statement, state);
          return statement;
        },
        () => encodePayload([PAYLOAD_FORMAT, "prepare", statementId]),
        (payload) => {
          requirePayload(payload, "prepare", 3);
          if (payload[2] !== statementId) throw invalidReplay();
          return createStatementSurrogate(
            statementPrototype,
            statementStates,
            { ...state, surrogate: true },
          );
        },
      );
    }));
    for (const name of ["get", "all", "run"]) {
      restores.push(patchMethod(statementPrototype, name, function () {
        const state = statementStates.get(this.receiver);
        if (state === undefined) {
          return unsupportedLiveCall(this.original, this.receiver, this.arguments);
        }
        let request;
        try {
          request = createRequest(
            state.database,
            name,
            state.id,
            state.sql,
            this.arguments,
          );
        } catch {
          return unsupportedStatementCall(
            state,
            this.original,
            this.receiver,
            this.arguments,
          );
        }
        return executeDependency(
          request,
          () => {
            if (state.surrogate) throw invalidReplay();
            return Reflect.apply(this.original, this.receiver, this.arguments);
          },
          (value) => encodeStatementResult(name, value),
          (payload) => decodeStatementResult(name, payload),
        );
      }));
    }
    for (const name of [
      "columns",
      "iterate",
      "setAllowBareNamedParameters",
      "setAllowUnknownNamedParameters",
      "setReadBigInts",
      "setReturnArrays",
    ]) {
      restores.push(patchUnsupportedMethod(statementPrototype, name, statementStates));
    }
    for (const name of [
      "aggregate",
      "applyChangeset",
      "close",
      "createSession",
      "createTagStore",
      "deserialize",
      "enableDefensive",
      "enableLoadExtension",
      "function",
      "loadExtension",
      "location",
      "open",
      "serialize",
      "setAuthorizer",
      Symbol.dispose,
    ]) {
      restores.push(patchUnsupportedMethod(databasePrototype, name));
    }
    restores.push(patchUnsupportedMethod(sqliteModule, "backup"));
    restores.push(patchUnsupportedMethod(process, "dlopen"));
    restores.push(patchWorkerConstructor(workerThreads));
    return combineRestores(restores);
  } catch (error) {
    combineRestores(restores)();
    throw error;
  }
}

function createRequest(database, action, statementId, sql, arguments_) {
  const budget = createBudget();
  const sqlValue = boundedString(sql, budget);
  const bindings = encodeBindings(arguments_, budget);
  return dependencyRequest({
    encoding: "node-sqlite-json-v1",
    metadata: [],
    method: null,
    observationClass: "database",
    operation: "database-execute",
    payload: encodePayload([
      PAYLOAD_FORMAT,
      action,
      database.id,
      statementId,
      sqlValue,
      bindings,
    ]),
    protocol: "sqlite",
    target: database.id,
  });
}

function executeDependency(request, live, encode, decode) {
  let liveCalled = false;
  let liveResult;
  let liveThrew = false;
  let liveError;
  try {
    const translated = runDependency(request, () => {
      liveCalled = true;
      try {
        liveResult = live();
      } catch (error) {
        liveThrew = true;
        liveError = error;
        throw error;
      }
      return dependencyResponse({
        metadata: [],
        outcome: "response",
        payload: encode(liveResult),
        status: "complete",
      });
    });
    if (liveCalled) return liveResult;
    if (translated?.outcome !== "response" || !Buffer.isBuffer(translated.payload)) {
      throw invalidReplay();
    }
    return decode(decodePayload(translated.payload));
  } catch (error) {
    if (liveThrew) throw liveError;
    if (liveCalled) return liveResult;
    throw error;
  }
}

function allocateStatementId(database) {
  if (database.nextStatementId > MAX_STATEMENTS_PER_DATABASE) {
    throw adapterLimit();
  }
  const statementId = database.nextStatementId;
  database.nextStatementId += 1;
  return statementId;
}

function createStatementSurrogate(prototype, states, state) {
  const target = Object.create(prototype);
  const surrogate = new Proxy(target, {
    get(object, property, receiver) {
      if (property === "sourceSQL") return state.sql;
      if (property === "expandedSQL") {
        markDatabaseUnowned();
        throw unsupportedReplay();
      }
      return Reflect.get(object, property, receiver);
    },
    set() {
      markDatabaseUnowned();
      throw unsupportedReplay();
    },
  });
  states.set(surrogate, state);
  return surrogate;
}

function encodeStatementResult(action, value) {
  const budget = createBudget();
  if (action === "get") {
    const encoded = value === undefined ? ["none"] : ["row", encodeRow(value, budget)];
    return encodePayload([PAYLOAD_FORMAT, "get", encoded]);
  }
  if (action === "all") {
    if (!Array.isArray(value) || value.length > MAX_RESULT_ROWS) throw adapterLimit();
    const rows = value.map((row) => encodeRow(row, budget));
    return encodePayload([PAYLOAD_FORMAT, "all", rows]);
  }
  if (action === "run") {
    return encodePayload([PAYLOAD_FORMAT, "run", encodeObject(value, budget)]);
  }
  throw adapterInvalid();
}

function decodeStatementResult(action, payload) {
  requirePayload(payload, action, 3);
  if (action === "get") {
    const value = payload[2];
    if (!Array.isArray(value) || value.length < 1) throw invalidReplay();
    if (value[0] === "none" && value.length === 1) return undefined;
    if (value[0] === "row" && value.length === 2) return decodeRow(value[1]);
    throw invalidReplay();
  }
  if (action === "all") {
    const rows = payload[2];
    if (!Array.isArray(rows) || rows.length > MAX_RESULT_ROWS) throw invalidReplay();
    return rows.map(decodeRow);
  }
  if (action === "run") return decodeObject(payload[2]);
  throw invalidReplay();
}

function encodeBindings(arguments_, budget) {
  if (!Array.isArray(arguments_) || arguments_.length > MAX_BIND_ARGUMENTS) {
    throw adapterLimit();
  }
  return arguments_.map((value) => {
    if (isRecord(value)) return ["named", encodeObject(value, budget)];
    return ["value", encodeSqliteValue(value, budget)];
  });
}

function encodeRow(value, budget) {
  if (Array.isArray(value)) {
    if (value.length > MAX_OBJECT_FIELDS) throw adapterLimit();
    return ["array", value.map((entry) => encodeSqliteValue(entry, budget))];
  }
  return ["object", encodeObject(value, budget)];
}

function decodeRow(value) {
  if (!Array.isArray(value) || value.length !== 2) throw invalidReplay();
  if (value[0] === "array") {
    if (!Array.isArray(value[1]) || value[1].length > MAX_OBJECT_FIELDS) {
      throw invalidReplay();
    }
    return value[1].map(decodeSqliteValue);
  }
  if (value[0] === "object") return decodeObject(value[1]);
  throw invalidReplay();
}

function encodeObject(value, budget) {
  if (!isRecord(value)) throw adapterInvalid();
  const keys = Object.keys(value);
  if (keys.length > MAX_OBJECT_FIELDS) throw adapterLimit();
  const prototype = Object.getPrototypeOf(value) === null ? "null" : "object";
  const fields = keys.map((key) => [
    boundedString(key, budget),
    encodeSqliteValue(value[key], budget),
  ]);
  return [prototype, fields];
}

function decodeObject(value) {
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    !["null", "object"].includes(value[0]) ||
    !Array.isArray(value[1]) ||
    value[1].length > MAX_OBJECT_FIELDS
  ) {
    throw invalidReplay();
  }
  const result = value[0] === "null" ? Object.create(null) : {};
  for (const field of value[1]) {
    if (
      !Array.isArray(field) ||
      field.length !== 2 ||
      typeof field[0] !== "string" ||
      Object.hasOwn(result, field[0])
    ) {
      throw invalidReplay();
    }
    Object.defineProperty(result, field[0], {
      configurable: true,
      enumerable: true,
      value: decodeSqliteValue(field[1]),
      writable: true,
    });
  }
  return result;
}

function encodeSqliteValue(value, budget) {
  if (value === null) return ["null"];
  if (typeof value === "string") return ["string", boundedString(value, budget)];
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw adapterInvalid();
    return ["number", Object.is(value, -0) ? "-0" : String(value)];
  }
  if (typeof value === "bigint") return ["bigint", String(value)];
  if (value instanceof Uint8Array) {
    spend(budget, value.byteLength);
    return ["blob", Buffer.from(value).toString("base64url")];
  }
  throw adapterInvalid();
}

function decodeSqliteValue(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 2) {
    throw invalidReplay();
  }
  if (value[0] === "null" && value.length === 1) return null;
  if (value[0] === "string" && typeof value[1] === "string") return value[1];
  if (value[0] === "number" && typeof value[1] === "string") {
    const number = Number(value[1]);
    if (!Number.isFinite(number)) throw invalidReplay();
    if (value[1] === "-0") return -0;
    if (String(number) !== value[1]) throw invalidReplay();
    return number;
  }
  if (
    value[0] === "bigint" &&
    typeof value[1] === "string" &&
    /^(0|-?[1-9][0-9]*)$/u.test(value[1])
  ) {
    return BigInt(value[1]);
  }
  if (value[0] === "blob" && typeof value[1] === "string") {
    const bytes = Buffer.from(value[1], "base64url");
    if (bytes.toString("base64url") !== value[1]) throw invalidReplay();
    return new Uint8Array(bytes);
  }
  throw invalidReplay();
}

function encodePayload(value) {
  let bytes;
  try {
    bytes = Buffer.from(JSON.stringify(value), "utf8");
  } catch {
    throw adapterInvalid();
  }
  if (bytes.length === 0 || bytes.length > MAX_ADAPTER_PAYLOAD_BYTES) {
    throw adapterLimit();
  }
  return bytes;
}

function decodePayload(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_ADAPTER_PAYLOAD_BYTES) {
    throw invalidReplay();
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return JSON.parse(text);
  } catch {
    throw invalidReplay();
  }
}

function requirePayload(payload, action, length) {
  if (
    !Array.isArray(payload) ||
    payload.length !== length ||
    payload[0] !== PAYLOAD_FORMAT ||
    payload[1] !== action
  ) {
    throw invalidReplay();
  }
}

function boundedString(value, budget) {
  if (typeof value !== "string") throw adapterInvalid();
  spend(budget, Buffer.byteLength(value, "utf8"));
  return value;
}

function createBudget() {
  return { remaining: MAX_ADAPTER_PAYLOAD_BYTES };
}

function spend(budget, bytes) {
  if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > budget.remaining) {
    throw adapterLimit();
  }
  budget.remaining -= bytes;
}

function patchUnsupportedMethod(owner, name, states = null) {
  return patchMethod(owner, name, function () {
    const state = states?.get(this.receiver);
    if (state?.surrogate) {
      markDatabaseUnowned();
      throw unsupportedReplay();
    }
    return unsupportedLiveCall(this.original, this.receiver, this.arguments);
  });
}

function unsupportedStatementCall(state, original, receiver, arguments_) {
  markDatabaseUnowned();
  if (state.surrogate) throw unsupportedReplay();
  return Reflect.apply(original, receiver, arguments_);
}

function unsupportedLiveCall(original, receiver, arguments_) {
  markDatabaseUnowned();
  return Reflect.apply(original, receiver, arguments_);
}

function markDatabaseUnowned() {
  const context = currentOperationContext();
  if (context !== null) {
    markOperationUnowned(context, "database", UNSUPPORTED_EVIDENCE);
  }
}

function patchWorkerConstructor(owner) {
  const original = owner.Worker;
  if (typeof original !== "function") throw hookUnavailable();
  const replacement = function Worker(...arguments_) {
    markDatabaseUnowned();
    if (new.target === undefined) {
      return Reflect.apply(original, this, arguments_);
    }
    return Reflect.construct(original, arguments_, new.target);
  };
  Object.setPrototypeOf(replacement, original);
  replacement.prototype = original.prototype;
  return patchValue(owner, "Worker", replacement);
}

function patchMethod(owner, name, implementation) {
  const original = owner?.[name];
  if (typeof original !== "function") throw hookUnavailable();
  const replacement = function (...arguments_) {
    return Reflect.apply(implementation, {
      arguments: arguments_,
      original,
      receiver: this,
    }, arguments_);
  };
  return patchValue(owner, name, replacement);
}

function patchValue(owner, name, replacement) {
  const descriptor = Object.getOwnPropertyDescriptor(owner, name);
  if (
    descriptor === undefined ||
    !("value" in descriptor) ||
    descriptor.configurable !== true
  ) {
    throw hookUnavailable();
  }
  Object.defineProperty(owner, name, { ...descriptor, value: replacement });
  return () => {
    const current = Object.getOwnPropertyDescriptor(owner, name);
    if (current?.value === replacement) Object.defineProperty(owner, name, descriptor);
  };
}

function combineRestores(restores) {
  return () => {
    for (let index = restores.length - 1; index >= 0; index -= 1) {
      restores[index]();
    }
  };
}

function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === null || prototype === Object.prototype;
}

function adapterInvalid() {
  const error = new TypeError("The SQLite adapter value is invalid.");
  error.code = "ERR_REPROIT_SQLITE_ADAPTER";
  return error;
}

function adapterLimit() {
  const error = new RangeError("The SQLite adapter limit was reached.");
  error.code = "ERR_REPROIT_SQLITE_ADAPTER";
  return error;
}

function hookUnavailable() {
  return new Error("The Node.js SQLite hook is unavailable.");
}

function invalidReplay() {
  const error = new Error("The recorded SQLite dependency is invalid.");
  error.code = "ERR_REPROIT_SQLITE_REPLAY";
  return error;
}

function unsupportedReplay() {
  const error = new Error("The recorded SQLite operation is unsupported.");
  error.code = "ERR_REPROIT_SQLITE_REPLAY";
  return error;
}
