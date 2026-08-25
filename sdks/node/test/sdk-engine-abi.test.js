import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  NATIVE_ENGINE_ABI_CONTRACT_DIGEST,
  NATIVE_ENGINE_ABI_VERSION,
  NATIVE_ENGINE_CALL_FORMAT,
  NATIVE_ENGINE_LIBRARIES,
  NATIVE_ENGINE_DEPENDENCY_CONTRACT,
  NATIVE_ENGINE_MAX_CALL_BYTES,
  NATIVE_ENGINE_MAX_EVIDENCE_BYTES,
  NATIVE_ENGINE_MAX_OBSERVATION_ADAPTERS,
  NATIVE_ENGINE_MAX_OBSERVATION_CHUNK_BYTES,
  NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES,
  NATIVE_ENGINE_MAX_OBSERVATION_SESSIONS,
  NATIVE_ENGINE_MAX_OBSERVATION_SESSIONS_PER_OPERATION,
  NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES,
  NATIVE_ENGINE_MAX_SINK_WAIT_MS,
  NATIVE_ENGINE_MAX_SINK_WAITERS,
  NATIVE_ENGINE_OPERATIONS,
  NATIVE_ENGINE_OBSERVATION_ACTIONS,
  NATIVE_ENGINE_OBSERVATION_CONTRACT,
  NATIVE_ENGINE_REQUIRED_OBSERVATION_CLASSES,
  NATIVE_ENGINE_RESPONSE_CAPACITY,
  NATIVE_ENGINE_RESPONSE_FORMAT,
  NATIVE_ENGINE_SYMBOLS,
} from "../src/native-engine.js";

const ABI_URL = new URL(
  "../../../crates/reproit-sdk-engine/sdk-engine-abi.json",
  import.meta.url,
);
const LOADER_URL = new URL(
  "../native/reproit-sdk-engine-loader.c",
  import.meta.url,
);

test("native bridge constants match the canonical ABI", () => {
  const abiBytes = readFileSync(ABI_URL);
  const abi = JSON.parse(abiBytes);
  const libraries = Object.fromEntries(
    abi.libraries.map((value) => [value.platform, value.name]),
  );
  assert.equal(NATIVE_ENGINE_ABI_VERSION, abi.abi_version);
  assert.equal(NATIVE_ENGINE_CALL_FORMAT, abi.request.format);
  assert.equal(NATIVE_ENGINE_MAX_CALL_BYTES, abi.request.maximum_bytes);
  assert.equal(NATIVE_ENGINE_MAX_EVIDENCE_BYTES, abi.limits.evidence_bytes);
  assert.equal(
    NATIVE_ENGINE_MAX_OBSERVATION_ADAPTERS,
    abi.limits.observation_adapters,
  );
  assert.equal(
    NATIVE_ENGINE_MAX_OBSERVATION_CHUNK_BYTES,
    abi.limits.observation_chunk_bytes,
  );
  assert.equal(
    NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES,
    abi.limits.observation_response_read_bytes,
  );
  assert.equal(
    NATIVE_ENGINE_MAX_OBSERVATION_SESSIONS,
    abi.limits.observation_sessions,
  );
  assert.equal(
    NATIVE_ENGINE_MAX_OBSERVATION_SESSIONS_PER_OPERATION,
    abi.limits.observation_sessions_per_operation,
  );
  assert.equal(
    NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES,
    abi.limits.semantic_dependency_record_bytes,
  );
  assert.equal(NATIVE_ENGINE_MAX_SINK_WAIT_MS, abi.limits.sink_wait_ms);
  assert.equal(NATIVE_ENGINE_MAX_SINK_WAITERS, abi.limits.sinks);
  assert.equal(NATIVE_ENGINE_RESPONSE_FORMAT, abi.response.format);
  assert.equal(
    NATIVE_ENGINE_RESPONSE_CAPACITY,
    abi.response.output_capacity_bytes,
  );
  assert.deepEqual(NATIVE_ENGINE_LIBRARIES, libraries);
  assert.deepEqual(NATIVE_ENGINE_SYMBOLS, abi.symbols);
  assert.deepEqual(
    [...NATIVE_ENGINE_OPERATIONS].sort(),
    [...abi.operations].sort(),
  );
  assert.deepEqual(
    NATIVE_ENGINE_OBSERVATION_ACTIONS,
    abi.observation_actions,
  );
  assert.deepEqual(
    NATIVE_ENGINE_OBSERVATION_CONTRACT,
    abi.observation_contract,
  );
  assert.deepEqual(
    NATIVE_ENGINE_REQUIRED_OBSERVATION_CLASSES,
    abi.required_observation_classes,
  );
  assert.deepEqual(NATIVE_ENGINE_DEPENDENCY_CONTRACT, abi.dependency_contract);
  assert.equal(
    NATIVE_ENGINE_ABI_CONTRACT_DIGEST,
    `sha256:${createHash("sha256").update(abiBytes).digest("hex")}`,
  );

  const loader = readFileSync(LOADER_URL, "utf8");
  assert.match(
    loader,
    new RegExp(`#define MAX_CALL_BYTES \\(\\(size_t\\)${abi.request.maximum_bytes}\\)`),
  );
  assert.match(
    loader,
    new RegExp(
      `#define RESPONSE_CAPACITY \\(` +
        `\\(size_t\\)${abi.response.output_capacity_bytes}\\)`,
    ),
  );
  for (const symbol of Object.values(abi.symbols)) {
    assert.equal(loader.includes(`"${symbol}"`), true);
  }
  for (const library of new Set(abi.libraries.map((value) => value.name))) {
    assert.equal(loader.includes(`"${library}"`), true);
  }
});
