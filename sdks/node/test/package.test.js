import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

const packageRoot = path.resolve(import.meta.dirname, "..");

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
    assert.ok(entries.includes("package/src/public.js"));
    assert.ok(entries.includes("package/src/engine-operation.js"));
    assert.ok(entries.includes("package/src/process-resources.js"));
    assert.ok(entries.includes("package/src/native-engine.js"));
    assert.ok(entries.includes("package/src/observation-adapters.js"));
    assert.ok(entries.includes("package/native/reproit-sdk-engine-loader.c"));
    assert.equal(entries.includes("package/src/index.js"), false);
    assert.equal(entries.includes("package/src/managed-candidate.js"), false);
    assert.equal(entries.includes("package/src/managed-sink.js"), false);
    assert.equal(entries.includes("package/src/managed-upload.js"), false);
    assert.equal(entries.includes("package/src/official-managed.js"), false);
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
    assert.equal(typeof installed.ManagedEngineProject, "function");
    assert.equal(typeof installed.runOperation, "function");
    assert.equal("loadNativeEngine" in installed, false);
    assert.equal("NativeEngineCallError" in installed, false);
    assert.equal("MemorySink" in installed, false);
    assert.equal("TlsCloudStagingSink" in installed, false);
    assert.throws(() => requireFromFixture.resolve("@reproit/sdk/http"));
    assert.throws(
      () => new installed.ManagedEngineProject(null, 1, () => "not-used"),
      /Use ManagedEngineProject\.open\(\)\./,
    );
  } finally {
    fs.rmSync(temporaryRoot, { force: true, recursive: true });
  }
});

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
