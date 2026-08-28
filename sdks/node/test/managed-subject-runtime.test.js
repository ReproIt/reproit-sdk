// Negative controls for Node.js runtime evidence and launch options.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  runtimeEvidence,
  subjectFixture,
} from "./managed-subject-fixtures.js";
import { ManagedError } from "../src/subject-protocol.js";
import {
  packageNodeSubjectWithRuntimeEvidence,
  validateNodeRuntimeArguments,
} from "../src/managed-subject.js";

test("runtime packaging preserves supported Node launch flags", () => {
  assert.doesNotThrow(
    () => validateNodeRuntimeArguments(process.execArgv),
    JSON.stringify(process.execArgv),
  );
});

test("runtime packaging binds the adapter implementation module", (t) => {
  const sourcePath = path.resolve(
    import.meta.dirname,
    "../src/runtime-observation-adapters.js",
  );
  const subject = packageNodeSubjectWithRuntimeEvidence(
    path.resolve(import.meta.dirname, "../src/public.js"),
    runtimeEvidence(t),
  );
  try {
    const digest = `sha256:${createHash("sha256")
      .update(fs.readFileSync(sourcePath))
      .digest("hex")}`;
    assert.ok(subject.manifest.modules.some(
      (module) => module.module_digest === digest,
    ));
  } finally {
    subject.dispose();
  }
});

test("runtime packaging rejects a changed loaded-module report", (t) => {
  const fixture = subjectFixture(t);
  const evidence = runtimeEvidence(t);
  evidence.verify = () => {
    throw new ManagedError(
      "INCOMPLETE_CANDIDATE",
      "The loaded Node.js runtime modules changed during packaging.",
    );
  };
  assert.throws(
    () => packageNodeSubjectWithRuntimeEvidence(fixture.entry, evidence),
    (error) =>
      error instanceof ManagedError && error.code === "INCOMPLETE_CANDIDATE",
  );
});

test("runtime packaging rejects NODE_OPTIONS", () => {
  assert.throws(
    () => validateNodeRuntimeArguments([], "--require=/host/preload.js"),
    (error) => error instanceof ManagedError && error.code === "UNSUPPORTED",
  );
});

test("runtime packaging rejects debugger launch flags", () => {
  assert.throws(
    () => validateNodeRuntimeArguments(["--inspect=127.0.0.1:0"]),
    (error) => error instanceof ManagedError && error.code === "UNSUPPORTED",
  );
});

test("runtime packaging rejects host-path launch flags", () => {
  assert.throws(
    () => validateNodeRuntimeArguments(["--require=/host/preload.js"]),
    (error) => error instanceof ManagedError && error.code === "UNSUPPORTED",
  );
});

test("runtime packaging rejects ambiguous dependency roots", (t) => {
  const fixture = subjectFixture(t);
  const serviceRoot = path.join(fixture.root, "service");
  fs.mkdirSync(path.join(serviceRoot, "node_modules", "local"), {
    recursive: true,
  });
  fs.writeFileSync(
    path.join(serviceRoot, "package.json"),
    JSON.stringify({ name: "service", version: "1.0.0" }),
  );
  const entry = path.join(serviceRoot, "main.js");
  fs.writeFileSync(entry, "throw new Error('fixture');\n");
  fs.writeFileSync(
    path.join(serviceRoot, "node_modules", "local", "package.json"),
    JSON.stringify({ name: "local", version: "1.0.0" }),
  );
  assert.throws(
    () => packageNodeSubjectWithRuntimeEvidence(entry, runtimeEvidence(t)),
    (error) => error instanceof ManagedError && error.code === "UNSUPPORTED",
  );
});
