import assert from "node:assert/strict";
import test from "node:test";

import {
  ManagedEngineProject,
  runOperation,
} from "../src/public.js";
import {
  createManagedEngineProjectForTest,
  currentOperationContext,
  markOperationUnowned,
  openObservation,
} from "../src/engine-operation.js";

class FakeBridge {
  calls = [];

  operationBegin(engineHandle, begin) {
    this.calls.push(["begin", engineHandle, begin]);
    return { operationHandle: 2, operationId: "op_fixture" };
  }

  operationInput(handle, value) {
    this.calls.push(["input", handle, value]);
  }

  observationOpen(handle, kind, parent) {
    this.calls.push(["observation-open", handle, kind, parent]);
    return { observationHandle: 4, sessionPosition: 7 };
  }

  observationWrite(handle, stream, chunk) {
    this.calls.push(["observation-write", handle, stream, chunk]);
  }

  observationDispatch(handle) {
    this.calls.push(["observation-dispatch", handle]);
    return "capture";
  }

  observationRead(handle) {
    this.calls.push(["observation-read", handle]);
    return { chunk: Buffer.alloc(0), eof: true };
  }

  observationFinish(handle, outcome, position) {
    this.calls.push(["observation-finish", handle, outcome, position]);
  }

  observationAbandon(handle) {
    this.calls.push(["observation-abandon", handle]);
  }

  operationUnowned(handle, kind, evidence, parent) {
    this.calls.push(["unowned", handle, kind, evidence, parent]);
  }

  operationCloseWorld(handle, completion) {
    this.calls.push(["close-world", handle, completion]);
  }

  operationSucceed(handle) {
    this.calls.push(["succeed", handle]);
  }

  operationAbandon(handle) {
    this.calls.push(["abandon", handle]);
  }

  operationFail(handle, failure, token) {
    this.calls.push(["fail", handle, failure, token]);
    return 3;
  }

  sinkWait(handle, timeoutMilliseconds) {
    this.calls.push(["sink-wait", handle, timeoutMilliseconds]);
    return true;
  }

  engineClose(handle) {
    this.calls.push(["engine-close", handle]);
  }
}

function fixture() {
  const bridge = new FakeBridge();
  return {
    bridge,
    project: createManagedEngineProjectForTest(
      bridge,
      1,
      () => "fixture-project-token",
    ),
  };
}

test("one public boundary supports every Backend completion", () => {
  for (const completion of [
    "return",
    "stream-end",
    "acknowledgment",
    "task-end",
  ]) {
    const { bridge, project } = fixture();
    const result = runOperation(
      project,
      {
        begin: { operation_kind: "request-response" },
        completion,
        inputs: [{ input_index: 0 }, { input_index: 1 }],
      },
      (context) => context.operationId,
      () => null,
    );
    assert.equal(result, "op_fixture");
    assert.deepEqual(
      bridge.calls.map((call) => call[0]),
      ["begin", "input", "input", "succeed"],
    );
    assert.equal(bridge.calls.some((call) => call[0] === "close-world"), false);
    assert.equal(bridge.calls.some((call) => call[0] === "fail"), false);
  }
});

test("semantic observation sessions preserve order, bytes, and parents", () => {
  const { bridge, project } = fixture();
  assert.equal(
    runOperation(
      project,
      { begin: {}, completion: "return", inputs: [] },
      (context) => {
        const session = openObservation(context, "database", "op_parent");
        assert.notEqual(session, null);
        assert.equal(session.writeRequest(Buffer.from("request")), true);
        assert.equal(session.dispatch(), "capture");
        assert.equal(session.writeResponse(Buffer.from("response")), true);
        assert.equal(session.finish("response"), true);
        markOperationUnowned(context, "filesystem", Buffer.from("unowned"));
        return "result";
      },
      () => null,
    ),
    "result",
  );
  assert.deepEqual(bridge.calls[1], [
    "observation-open",
    2,
    "database",
    "op_parent",
  ]);
  assert.deepEqual(bridge.calls[2], [
    "observation-write",
    4,
    "request",
    Buffer.from("request"),
  ]);
  assert.deepEqual(bridge.calls[3], ["observation-dispatch", 4]);
  assert.deepEqual(bridge.calls[4], [
    "observation-write",
    4,
    "response",
    Buffer.from("response"),
  ]);
  assert.deepEqual(bridge.calls[5], [
    "observation-finish",
    4,
    "response",
    7,
  ]);
  assert.deepEqual(bridge.calls[6], [
    "unowned",
    2,
    "filesystem",
    Buffer.from("unowned"),
    null,
  ]);
});

test("invalid observation transition abandons capture only", () => {
  const { bridge, project } = fixture();
  bridge.observationDispatch = (handle) => {
    bridge.calls.push(["observation-dispatch", handle]);
    throw new Error("private engine detail");
  };
  assert.equal(
    runOperation(
      project,
      { begin: {}, completion: "return", inputs: [] },
      (context) => {
        const session = openObservation(context, "database");
        assert.notEqual(session, null);
        assert.equal(session.writeRequest(Buffer.from("request")), true);
        assert.equal(session.dispatch(), null);
        return "application-result";
      },
      () => null,
    ),
    "application-result",
  );
  assert.equal(
    bridge.calls.some(
      (call) => call[0] === "observation-abandon" && call[1] === 4,
    ),
    true,
  );
  assert.equal(
    bridge.calls.some((call) => call[0] === "abandon" && call[1] === 2),
    true,
  );
  assert.equal(
    bridge.calls.some((call) => call[0] === "succeed" && call[1] === 2),
    false,
  );
});

test("failure identity reaches the engine and the original error is rethrown", async () => {
  const { bridge, project } = fixture();
  const original = new Error("application failure");
  const failure = { format: "reproit.failure-identity.v1" };
  assert.throws(
    () =>
      runOperation(
        project,
        { begin: {}, completion: "return", inputs: [] },
        () => {
          throw original;
        },
        () => failure,
      ),
    (error) => error === original,
  );
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(bridge.calls.slice(1, 3), [
    ["close-world", 2, "return"],
    ["fail", 2, failure, "fixture-project-token"],
  ]);
  assert.deepEqual(bridge.calls.at(-1), ["sink-wait", 3, 0]);
});

test("capture failure and AbortError do not change application behavior", async () => {
  const bridge = new FakeBridge();
  bridge.operationBegin = () => {
    throw new Error("local capture unavailable");
  };
  const project = createManagedEngineProjectForTest(
    bridge,
    1,
    () => "fixture-project-token",
  );
  assert.equal(
    runOperation(
      project,
      { begin: {}, completion: "return", inputs: [] },
      () => "application-result",
      () => null,
    ),
    "application-result",
  );

  const active = fixture();
  const cancellation = new Error("cancelled");
  cancellation.name = "AbortError";
  await assert.rejects(
    runOperation(
      active.project,
      { begin: {}, completion: "return", inputs: [] },
      async () => {
        throw cancellation;
      },
      () => assert.fail("Cancellation was translated."),
    ),
    (error) => error === cancellation,
  );
  assert.deepEqual(active.bridge.calls.at(-1), ["abandon", 2]);
  assert.equal(currentOperationContext(), null);
});

test("nested operations restore their parent and caller contexts", () => {
  const { bridge, project } = fixture();
  let sequence = 0;
  bridge.operationBegin = (engineHandle, begin) => {
    sequence += 1;
    bridge.calls.push(["begin", engineHandle, begin]);
    return { operationHandle: sequence + 1, operationId: `op_${sequence}` };
  };
  assert.equal(currentOperationContext(), null);
  const result = runOperation(
    project,
    { begin: {}, completion: "return", inputs: [] },
    (outerContext) => {
      assert.equal(currentOperationContext(), outerContext);
      const innerId = runOperation(
        project,
        { begin: {}, completion: "return", inputs: [] },
        (innerContext) => {
          assert.equal(currentOperationContext(), innerContext);
          assert.notEqual(innerContext, outerContext);
          return innerContext.operationId;
        },
        () => null,
      );
      assert.equal(currentOperationContext(), outerContext);
      return [outerContext.operationId, innerId];
    },
    () => null,
  );
  assert.deepEqual(result, ["op_1", "op_2"]);
  assert.equal(currentOperationContext(), null);
});

test("concurrent async operations keep distinct contexts", async () => {
  const { bridge, project } = fixture();
  let sequence = 0;
  bridge.operationBegin = () => {
    sequence += 1;
    return { operationHandle: sequence + 1, operationId: `op_${sequence}` };
  };
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  let ready = 0;
  let bothReady;
  const readyGate = new Promise((resolve) => {
    bothReady = resolve;
  });
  const operation = async (context) => {
    assert.equal(currentOperationContext(), context);
    ready += 1;
    if (ready === 2) bothReady();
    await gate;
    await Promise.resolve();
    assert.equal(currentOperationContext(), context);
    return context.operationId;
  };
  const first = runOperation(
    project,
    { begin: {}, completion: "return", inputs: [] },
    operation,
    () => null,
  );
  const second = runOperation(
    project,
    { begin: {}, completion: "return", inputs: [] },
    operation,
    () => null,
  );
  await readyGate;
  release();
  assert.deepEqual(await Promise.all([first, second]), ["op_1", "op_2"]);
  assert.equal(currentOperationContext(), null);
});

test("exceptions restore the caller context", () => {
  const { project } = fixture();
  const original = new Error("application failure");
  assert.throws(
    () =>
      runOperation(
        project,
        { begin: {}, completion: "return", inputs: [] },
        (context) => {
          assert.equal(currentOperationContext(), context);
          throw original;
        },
        () => null,
      ),
    (error) => error === original,
  );
  assert.equal(currentOperationContext(), null);
});

test("detached work cannot retain a closed operation", async () => {
  const { project } = fixture();
  let inspectDetached;
  const detached = new Promise((resolve) => {
    inspectDetached = resolve;
  });
  assert.equal(
    runOperation(
      project,
      { begin: {}, completion: "return", inputs: [] },
      (context) => {
        assert.equal(currentOperationContext(), context);
        setTimeout(() => inspectDetached(currentOperationContext()), 0);
        return "application-result";
      },
      () => null,
    ),
    "application-result",
  );
  assert.equal(await detached, null);
});
