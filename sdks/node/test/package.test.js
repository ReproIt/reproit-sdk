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
    assert.ok(entries.includes("package/src/register.d.ts"));
    assert.ok(entries.includes("package/src/register.js"));
    assert.ok(entries.includes("package/src/engine-operation.js"));
    assert.ok(entries.includes("package/src/process-resources.js"));
    assert.ok(entries.includes("package/src/native-engine.js"));
    assert.ok(entries.includes("package/src/observation-adapters.js"));
    assert.ok(entries.includes("package/src/runtime-observation-adapters.js"));
    assert.ok(entries.includes("package/src/semantic-dependency.js"));
    assert.ok(entries.includes("package/src/semantic-observation.js"));
    assert.ok(entries.includes("package/src/sqlite-adapter.js"));
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
    const registerEntry = requireFromFixture.resolve("@reproit/sdk/register");
    const installed = await import(pathToFileURL(entry).href);
    assert.equal(typeof installed.ManagedEngineProject, "function");
    assert.equal(typeof installed.runOperation, "function");
    assert.equal("loadNativeEngine" in installed, false);
    assert.equal("NativeEngineCallError" in installed, false);
    assert.equal("MemorySink" in installed, false);
    assert.equal("TlsCloudStagingSink" in installed, false);
    assert.throws(() => requireFromFixture.resolve("@reproit/sdk/http"));
    assert.throws(
      () => requireFromFixture.resolve("@reproit/sdk/semantic-dependency"),
    );
    assert.throws(
      () => new installed.ManagedEngineProject(null, 1, () => "not-used"),
      /Use ManagedEngineProject\.open\(\)\./,
    );
    verifyRegisterPreload(fixtureRoot, registerEntry);
  } finally {
    fs.rmSync(temporaryRoot, { force: true, recursive: true });
  }
});

function verifyRegisterPreload(fixtureRoot, registerEntry) {
  const sourceRoot = path.dirname(registerEntry);
  const runtimeEntry = pathToFileURL(
    path.join(sourceRoot, "runtime-observation-adapters.js"),
  ).href;
  const engineEntry = pathToFileURL(
    path.join(sourceRoot, "engine-operation.js"),
  ).href;
  const applicationPath = path.join(fixtureRoot, "application.mjs");
  fs.writeFileSync(
    applicationPath,
    preloadApplicationSource(runtimeEntry, engineEntry),
  );
  const output = execFileSync(
    process.execPath,
    ["--import", "@reproit/sdk/register", applicationPath],
    {
      cwd: fixtureRoot,
      encoding: "utf8",
      maxBuffer: 16 * 1_024,
    },
  );
  assert.equal(output, "register-preload-pass\n");

  const nonce = "0123456789abcdef".repeat(4);
  const markerPath = path.join(fixtureRoot, "probe-application-ran");
  const probeApplicationPath = path.join(fixtureRoot, "probe-application.mjs");
  fs.writeFileSync(
    probeApplicationPath,
    `import fs from "node:fs"; fs.writeFileSync(${JSON.stringify(markerPath)}, "ran");\n`,
  );
  const probeOutput = execFileSync(
    process.execPath,
    ["--import", "@reproit/sdk/register", probeApplicationPath],
    {
      cwd: fixtureRoot,
      encoding: "utf8",
      env: { ...process.env, REPROIT_INTERNAL_CAPTURE_PROBE: nonce },
      maxBuffer: 16 * 1_024,
    },
  );
  assert.equal(probeOutput, `reproit.capture-probe.v1:nodejs:${nonce}\n`);
  assert.equal(fs.existsSync(markerPath), false);
}

function preloadApplicationSource(runtimeEntry, engineEntry) {
  return `
import assert from "node:assert/strict";
import {
  runtimeObservationAdapterStateForTest,
} from ${JSON.stringify(runtimeEntry)};
import {
  openManagedEngineProjectWithForTest,
} from ${JSON.stringify(engineEntry)};

const startupDate = Date;
assert.deepEqual(runtimeObservationAdapterStateForTest(), {
  classes: [
    "clock", "database", "environment", "filesystem", "outbound-http", "queue",
    "randomness",
  ],
  leases: 1,
});
const registerModule = await import("@reproit/sdk/register");
assert.deepEqual(Object.keys(registerModule), []);
assert.equal(runtimeObservationAdapterStateForTest().leases, 1);

const bridge = {
  engineClose() {},
  engineOpen() { return 7; },
};
const subject = {
  dispose() {},
  manifest: {},
  objects: [],
};
const project = openManagedEngineProjectWithForTest({
  buildRepositoryId: "repository",
  projectTokenProvider: () => "unused-test-value",
  projectToml: "[project]",
  sourceRevision: "revision",
}, bridge, subject);
assert.equal(runtimeObservationAdapterStateForTest().leases, 2);
project.close();
assert.equal(runtimeObservationAdapterStateForTest().leases, 1);
assert.equal(Date, startupDate);
process.stdout.write("register-preload-pass\\n");
`;
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
