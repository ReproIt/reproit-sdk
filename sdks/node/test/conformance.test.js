import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CaptureError,
  MAX_ACTIVE_OPERATIONS,
  Sdk,
  canonicalBytes,
  runDeliveredWork,
  runOperation,
  runPreparedOperation,
  runStreamOperation,
} from "../src/index.js";
import { wrapHttpHandler } from "./http-support.js";
import { MemorySink } from "./memory-sink.js";
import "./setup.js";

const positive = JSON.parse(
  fs.readFileSync(process.env.REPROIT_PROTOCOL_VECTORS, "utf8"),
).positive;
const value = (name) => positive[name].value;

function fixture(sink = new MemorySink()) {
  const expected = value("candidate");
  const start = {
    captureId: expected.capture_id,
    deployment: expected.deployment,
    operationId: expected.operation_id,
    worldId: expected.world_id,
  };
  return { expected, sdk: new Sdk(sink), sink, start };
}

function fail(sdk, start) {
  sdk.begin(start, value("operation_begin_payload"));
  sdk.recordInput(start.operationId, value("operation_input_payload"));
  sdk.fail(start.operationId, value("failure_payload"));
}

function dependencyCursor() {
  const cursorBytes = Buffer.from("node-http-transcript");
  return {
    adapter_id: "http-transcript",
    adapter_version: "1.0.0",
    causal_parent_id: null,
    cursor: cursorBytes.toString("base64url"),
    cursor_digest: `sha256:${createHash("sha256").update(cursorBytes).digest("hex")}`,
    format: "reproit.dependency-cursor.v1",
  };
}

test("failed candidate matches the language-neutral vector", () => {
  const { expected, sdk, sink, start } = fixture();
  fail(sdk, start);
  assert.deepEqual(sink.candidates, [canonicalBytes(expected)]);
  assert.equal(sdk.activeOperations, 0);
});

test("refreshed World does not bypass Failure suppression", () => {
  const { sdk, sink, start } = fixture();
  fail(sdk, start);
  fail(sdk, {
    ...start,
    captureId: "cap_01890f3e-7b1c-7cc0-8a1b-123456789ac3",
    operationId: "op_01890f3e-7b1c-7cc0-8a1b-123456789ac4",
    worldId: `sha256:${"a".repeat(64)}`,
  });
  assert.equal(sink.candidates.length, 1);
  assert.equal(sdk.recallCounters.eligible_failure_observed, 2);
  assert.equal(sdk.recallCounters.suppressed_exact_storm, 1);
});

test("one thousand exact Failures use one candidate token", () => {
  const { sdk, sink, start } = fixture();
  for (let index = 0; index < 1_000; index += 1) {
    const suffix = index.toString(16).padStart(12, "0");
    fail(sdk, {
      ...start,
      captureId: `cap_01890f3e-7b1c-7cc0-8a1b-${suffix}`,
      operationId: `op_01890f3e-7b1c-7cc0-8a1b-${suffix}`,
    });
  }
  assert.equal(sink.candidates.length, 1);
  assert.equal(sdk.recallCounters.eligible_failure_observed, 1_000);
  assert.equal(sdk.recallCounters.suppressed_exact_storm, 999);
});

test("high-cardinality storm stops at candidate tokens", () => {
  const { sdk, sink, start } = fixture();
  for (let index = 0; index < 257; index += 1) {
    const failure = structuredClone(value("failure_payload"));
    failure.identity.stable_code = `storm-${index}`;
    failure.failure.identity = `sha256:${createHash("sha256")
      .update(canonicalBytes(failure.identity))
      .digest("hex")}`;
    const suffix = index.toString(16).padStart(12, "0");
    sdk.begin(
      {
        ...start,
        captureId: `cap_01890f3e-7b1c-7cc0-8a1b-${suffix}`,
        operationId: `op_01890f3e-7b1c-7cc0-8a1b-${suffix}`,
      },
      value("operation_begin_payload"),
    );
    sdk.fail(`op_01890f3e-7b1c-7cc0-8a1b-${suffix}`, failure);
  }
  assert.ok(sink.candidates.length <= 4);
  assert.ok(sdk.recallCounters.suppressed_high_cardinality_storm > 0);
});

test("process restart recovers exact queue capacity", async () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "reproit-node-queue-restart-"),
  );
  const resourceModule = new URL(
    "../src/process-resources.js",
    import.meta.url,
  ).href;
  const probe = `
import fs from 'node:fs';
import { reserveCandidate } from ${JSON.stringify(resourceModule)};
const statePath = process.argv[1];
let accepted = 0;
for (let index = 0; index < 17; index += 1) {
  if (reserveCandidate(1)) accepted += 1;
}
const descriptor = fs.openSync(statePath, 'wx', 0o600);
fs.writeFileSync(descriptor, JSON.stringify({ accepted }));
fs.fsyncSync(descriptor);
fs.closeSync(descriptor);
setInterval(() => {}, 1_000);
`;
  const waitForState = async (statePath) => {
    const deadline = performance.now() + 2_000;
    while (performance.now() < deadline) {
      if (fs.existsSync(statePath)) {
        return JSON.parse(fs.readFileSync(statePath, "utf8"));
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    throw new Error("The queue restart child did not publish its state.");
  };
  const start = (statePath) =>
    spawn(process.execPath, ["--input-type=module", "-e", probe, statePath], {
      stdio: "ignore",
    });
  let first;
  let second;
  try {
    first = start(path.join(directory, "first.json"));
    assert.equal(
      (await waitForState(path.join(directory, "first.json"))).accepted,
      16,
    );
    first.kill("SIGTERM");
    await new Promise((resolve) => first.once("exit", resolve));

    second = start(path.join(directory, "second.json"));
    assert.equal(
      (await waitForState(path.join(directory, "second.json"))).accepted,
      16,
    );
    second.kill("SIGTERM");
    await new Promise((resolve) => second.once("exit", resolve));
  } finally {
    if (first?.exitCode === null) first.kill("SIGKILL");
    if (second?.exitCode === null) second.kill("SIGKILL");
    fs.rmSync(directory, { force: true, recursive: true });
  }
});

test("incomplete candidate makes no staged delivery request", () => {
  const { sdk, sink, start } = fixture();
  sdk.begin(start, value("operation_begin_payload"));
  const failure = structuredClone(value("failure_payload"));
  failure.failure.identity = `sha256:${"0".repeat(64)}`;
  assert.throws(() => sdk.fail(start.operationId, failure), CaptureError);
  assert.deepEqual(sink.candidates, []);
  assert.equal(sdk.recallCounters.candidate_incomplete, 1);
});

test("success, cancellation, and application behavior are exact", () => {
  const { sdk, sink, start } = fixture();
  sdk.begin(start, value("operation_begin_payload"));
  sdk.succeed(start.operationId);
  sdk.begin(start, value("operation_begin_payload"));
  sdk.cancel(start.operationId);
  assert.deepEqual(sink.candidates, []);
  const original = new Error("customer failure");
  assert.throws(
    () =>
      runOperation(
        sdk,
        start,
        value("operation_begin_payload"),
        [value("operation_input_payload")],
        () => {
          throw original;
        },
        () => value("failure_payload"),
      ),
    (error) => error === original,
  );
  assert.deepEqual(sink.candidates, [canonicalBytes(value("candidate"))]);
});

test("dependency cursor is ordered before the Failure", () => {
  const { sdk, sink, start } = fixture();
  sdk.begin(start, value("operation_begin_payload"));
  sdk.recordInput(start.operationId, value("operation_input_payload"));
  sdk.recordDependency(start.operationId, dependencyCursor());
  sdk.fail(start.operationId, value("failure_payload"));
  const candidate = JSON.parse(sink.candidates[0].toString("utf8"));
  assert.deepEqual(
    candidate.records.map((record) => record.kind),
    ["begin", "input", "dependency", "failure", "terminal"],
  );
  const terminal = JSON.parse(
    Buffer.from(candidate.records.at(-1).payload, "base64url").toString("utf8"),
  );
  assert.equal(terminal.event_count, 4);
});

test("stream and delivered-work boundaries preserve kind and input order", () => {
  for (const [kind, run] of [
    ["stream", runStreamOperation],
    ["delivered-work", runDeliveredWork],
  ]) {
    const { sdk, sink, start } = fixture();
    const begin = structuredClone(value("operation_begin_payload"));
    begin.operation_kind = kind;
    const failure = structuredClone(value("failure_payload"));
    failure.identity.operation_kind = kind;
    failure.failure.identity = `sha256:${createHash("sha256")
      .update(canonicalBytes(failure.identity))
      .digest("hex")}`;
    const secondInput = structuredClone(value("operation_input_payload"));
    const secondValue = Buffer.from("second-input");
    secondInput.input_index = 1;
    secondInput.value = secondValue.toString("base64url");
    secondInput.value_digest = `sha256:${createHash("sha256")
      .update(secondValue)
      .digest("hex")}`;
    const original = new Error(`${kind} customer failure`);
    assert.throws(
      () =>
        run(
          sdk,
          {
            begin,
            dependencies: [dependencyCursor()],
            inputs: [value("operation_input_payload"), secondInput],
            start,
          },
          () => {
            throw original;
          },
          () => failure,
        ),
      (error) => error === original,
    );
    assert.equal(sdk.activeOperations, 0);
    assert.equal(sink.candidates.length, 1);
    const candidateBytes = sink.candidates[0];
    const candidate = JSON.parse(candidateBytes.toString("utf8"));
    assert.deepEqual(candidateBytes, canonicalBytes(candidate));
    assert.deepEqual(
      candidate.records.map((record) => record.kind),
      ["begin", "input", "input", "dependency", "failure", "terminal"],
    );
    const decoded = candidate.records.map((record) =>
      JSON.parse(Buffer.from(record.payload, "base64url").toString("utf8")),
    );
    assert.equal(decoded[0].operation_kind, kind);
    assert.equal(decoded[2].input_index, 1);
    assert.equal(decoded.at(-2).identity.operation_kind, kind);
  }
});

test("specialized boundary with the wrong operation kind does not capture", () => {
  const { sdk, sink, start } = fixture();
  const result = runStreamOperation(
    sdk,
    {
      begin: value("operation_begin_payload"),
      dependencies: [],
      inputs: [value("operation_input_payload")],
      start,
    },
    () => "application-result",
    () => value("failure_payload"),
  );
  assert.equal(result, "application-result");
  assert.equal(sdk.activeOperations, 0);
  assert.deepEqual(sink.candidates, []);
});

test("unknown operation kind stops before candidate handoff", () => {
  const { sdk, sink, start } = fixture();
  const begin = structuredClone(value("operation_begin_payload"));
  begin.operation_kind = "unknown";
  const failure = structuredClone(value("failure_payload"));
  failure.identity.operation_kind = "unknown";
  failure.failure.identity = `sha256:${createHash("sha256")
    .update(canonicalBytes(failure.identity))
    .digest("hex")}`;
  sdk.begin(start, begin);
  assert.throws(() => sdk.fail(start.operationId, failure), CaptureError);
  assert.equal(sdk.activeOperations, 0);
  assert.deepEqual(sink.candidates, []);
});

test("prepared capture conversion failure preserves behavior and releases state", () => {
  const { sdk, sink, start } = fixture();
  const original = new Error("customer failure");
  assert.throws(
    () =>
      runPreparedOperation(
        sdk,
        {
          begin: value("operation_begin_payload"),
          dependencies: [],
          inputs: [value("operation_input_payload")],
          start,
        },
        () => {
          throw original;
        },
        () => {
          throw new CaptureError("Failure conversion failed.");
        },
      ),
    (error) => error === original,
  );
  assert.equal(sdk.activeOperations, 0);
  assert.equal(sdk.recallCounters.candidate_incomplete, 1);
  assert.deepEqual(sink.candidates, []);
});

test("invalid dependency cursor stops before candidate handoff", () => {
  const { sdk, sink, start } = fixture();
  sdk.begin(start, value("operation_begin_payload"));
  sdk.recordDependency(start.operationId, {
    ...dependencyCursor(),
    adapter_id: "HTTP transcript",
  });
  assert.throws(
    () => sdk.fail(start.operationId, value("failure_payload")),
    CaptureError,
  );
  assert.equal(sdk.activeOperations, 0);
  assert.equal(sdk.recallCounters.candidate_incomplete, 1);
  assert.deepEqual(sink.candidates, []);
});

test("capture setup and cleanup failures do not change application behavior", async () => {
  const { start } = fixture();
  const setupFailureSdk = {
    begin() {
      throw new CaptureError("The World token is unavailable.");
    },
    cancel() {},
  };
  let calls = 0;
  const result = await runOperation(
    setupFailureSdk,
    start,
    value("operation_begin_payload"),
    [],
    async () => {
      calls += 1;
      return "application-result";
    },
    () => value("failure_payload"),
  );
  assert.equal(result, "application-result");
  assert.equal(calls, 1);

  const cleanupFailureSdk = {
    begin() {},
    recordInput() {},
    succeed() {
      throw new CaptureError("The SDK cleanup failed.");
    },
  };
  assert.equal(
    await runOperation(
      cleanupFailureSdk,
      start,
      value("operation_begin_payload"),
      [],
      async () => "application-result",
      () => value("failure_payload"),
    ),
    "application-result",
  );
});

test("managed candidate does not use a private candidate sink", () => {
  const sink = {
    calls: 0,
    processingModes: new Set(["private"]),
    queuedBytes: 0,
    trySend() {
      this.calls += 1;
      return true;
    },
  };
  const { sdk, start } = fixture(sink);
  const managed = {
    ...start,
    deployment: structuredClone(start.deployment),
  };
  managed.deployment.processing_mode = "managed";
  sdk.begin(managed, value("operation_begin_payload"));
  assert.throws(
    () => sdk.fail(managed.operationId, value("failure_payload")),
    CaptureError,
  );
  assert.equal(sink.calls, 0);
  assert.equal(sdk.activeOperations, 0);
  assert.equal(sdk.recallCounters.candidate_incomplete, 1);
});

test("HTTP boundary preserves the application exception", () => {
  const { expected, sdk, sink, start } = fixture();
  const original = new Error("customer failure");
  const handler = wrapHttpHandler(
    sdk,
    () => ({
      begin: value("operation_begin_payload"),
      inputs: [value("operation_input_payload")],
      start,
    }),
    () => value("failure_payload"),
    () => {
      throw original;
    },
  );
  assert.throws(
    () => handler({}, {}),
    (error) => error === original,
  );
  assert.deepEqual(sink.candidates, [canonicalBytes(expected)]);
});

test("HTTP preparation failure does not change the handler result", async () => {
  const handler = wrapHttpHandler(
    {},
    () => {
      throw new CaptureError("The World token is unavailable.");
    },
    () => value("failure_payload"),
    async () => "handler-result",
  );
  assert.equal(await handler({}, {}), "handler-result");
});

test("oversized failure deletes the operation", () => {
  const { sdk, sink, start } = fixture();
  sdk.begin(start, value("operation_begin_payload"));
  const failure = structuredClone(value("failure_payload"));
  failure.oversized = "x".repeat(65_536);
  assert.throws(() => sdk.fail(start.operationId, failure), CaptureError);
  assert.equal(sdk.activeOperations, 0);
  assert.deepEqual(sink.candidates, []);
});

test("active operation count is bounded", () => {
  const { sdk, sink, start } = fixture();
  const operationIds = [];
  for (let index = 0; index < MAX_ACTIVE_OPERATIONS; index += 1) {
    const operationId = `op_01890f3e-7b1c-7cc0-8a1b-${index.toString(16).padStart(12, "0")}`;
    sdk.begin({ ...start, operationId }, value("operation_begin_payload"));
    operationIds.push(operationId);
  }
  assert.throws(
    () =>
      sdk.begin(
        { ...start, operationId: "op_01890f3e-7b1c-7cc0-8a1b-000000000200" },
        value("operation_begin_payload"),
      ),
    CaptureError,
  );
  assert.equal(sdk.activeOperations, MAX_ACTIVE_OPERATIONS);
  assert.deepEqual(sink.candidates, []);
  for (const operationId of operationIds) sdk.cancel(operationId);
  assert.equal(sdk.activeOperations, 0);
});
