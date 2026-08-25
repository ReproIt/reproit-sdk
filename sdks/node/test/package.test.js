import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

import { MemorySink } from "./memory-sink.js";

const packageRoot = path.resolve(import.meta.dirname, "..");
// The portability harness copies the package outside the repository tree and
// supplies the canonical vectors through the environment. The relative path
// serves direct in-repository runs.
const protocolVectors = JSON.parse(
  fs.readFileSync(
    process.env.REPROIT_PROTOCOL_VECTORS ??
      path.resolve(packageRoot, "../../.core/specs/v1/protocol-vectors.json"),
    "utf8",
  ),
).positive;
const vector = (name) => structuredClone(protocolVectors[name].value);

test("package is deterministic, bounded, and installable from a local file", async () => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "reproit-node-package-"),
  );
  try {
    const first = pack(path.join(temporaryRoot, "first"));
    const second = pack(path.join(temporaryRoot, "second"));
    assert.deepEqual(first.bytes, second.bytes);
    assert.equal(first.digest, second.digest);

    const entries = execFileSync("tar", ["-tzf", first.path], {
      encoding: "utf8",
      maxBuffer: 64 * 1_024,
    })
      .trim()
      .split("\n");
    assert.ok(entries.includes("package/src/index.js"));
    assert.ok(entries.includes("package/src/candidate-validation.js"));
    assert.ok(entries.includes("package/src/process-resources.js"));
    assert.ok(entries.every((entry) => !entry.includes("/test/")));

    const fixtureRoot = path.join(temporaryRoot, "fixture");
    fs.mkdirSync(fixtureRoot);
    fs.writeFileSync(
      path.join(fixtureRoot, "package.json"),
      JSON.stringify({ private: true, type: "module" }),
    );
    execFileSync(
      "npm",
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--package-lock=false",
        first.path,
      ],
      { cwd: fixtureRoot, stdio: "pipe" },
    );
    const requireFromFixture = createRequire(
      path.join(fixtureRoot, "package.json"),
    );
    const entry = requireFromFixture.resolve("@reproit/sdk");
    const installed = await import(pathToFileURL(entry).href);
    assert.equal(typeof installed.Sdk, "function");
    assert.equal("MemorySink" in installed, false);
    assert.equal("TlsCloudStagingSink" in installed, false);
    assert.throws(() => requireFromFixture.resolve("@reproit/sdk/http"));
    exerciseInstalledArtifact(installed);
  } finally {
    fs.rmSync(temporaryRoot, { force: true, recursive: true });
  }
});

function exerciseInstalledArtifact(installed) {
  const candidate = vector("candidate");
  candidate.processing_mode = "managed";
  candidate.deployment.processing_mode = "managed";
  const start = {
    captureId: candidate.capture_id,
    deployment: candidate.deployment,
    operationId: candidate.operation_id,
    worldId: candidate.world_id,
  };
  const failureSink = new MemorySink();
  const failureSdk = new installed.Sdk(failureSink);
  const original = new Error("customer failure");
  assert.throws(
    () =>
      installed.runOperation(
        failureSdk,
        start,
        vector("operation_begin_payload"),
        [vector("operation_input_payload")],
        () => {
          throw original;
        },
        () => vector("failure_payload"),
      ),
    (error) => error === original,
  );
  assert.deepEqual(failureSink.candidates, [installed.canonicalBytes(candidate)]);
  assert.equal(failureSdk.activeOperations, 0);

  for (const [kind, run] of [
    ["stream", installed.runStreamOperation],
    ["delivered-work", installed.runDeliveredWork],
  ]) {
    const sink = new MemorySink();
    const sdk = new installed.Sdk(sink);
    const begin = vector("operation_begin_payload");
    begin.operation_kind = kind;
    const failure = vector("failure_payload");
    failure.identity.operation_kind = kind;
    failure.failure.identity = `sha256:${createHash("sha256")
      .update(installed.canonicalBytes(failure.identity))
      .digest("hex")}`;
    assert.throws(
      () =>
        run(
          sdk,
          { begin, dependencies: [], inputs: [], start },
          () => {
            throw original;
          },
          () => failure,
        ),
      (error) => error === original,
    );
    assert.equal(sink.candidates.length, 1);
    const encoded = sink.candidates[0];
    assert.deepEqual(
      encoded,
      installed.canonicalBytes(JSON.parse(Buffer.from(encoded).toString())),
    );
    assert.equal(sdk.activeOperations, 0);
  }
}

function pack(destination) {
  fs.mkdirSync(destination);
  const output = execFileSync(
    "npm",
    ["pack", "--json", "--pack-destination", destination],
    {
      cwd: packageRoot,
      encoding: "utf8",
      env: { ...process.env, SOURCE_DATE_EPOCH: "315532800" },
      maxBuffer: 64 * 1_024,
    },
  );
  const result = JSON.parse(output);
  assert.equal(result.length, 1);
  const archivePath = path.join(destination, result[0].filename);
  const bytes = fs.readFileSync(archivePath);
  return {
    bytes,
    digest: createHash("sha256").update(bytes).digest("hex"),
    path: archivePath,
  };
}
