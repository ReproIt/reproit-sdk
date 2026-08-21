// Processor capture conformance against specs/v1/processor-capture.json.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  captureProcessorCapabilities,
  deriveProcessorCapabilities,
  parseAuxvHwcap,
} from "../src/processor-capture.js";

const capturePath =
  process.env.REPROIT_PROCESSOR_CAPTURE ??
  path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "..",
    "..",
    "specs",
    "v1",
    "processor-capture.json",
  );

const MACHINES = new Map([
  ["architecture.x86-64", "x86_64"],
  ["architecture.arm64", "aarch64"],
]);

function captureContract() {
  return JSON.parse(fs.readFileSync(capturePath, "utf8"));
}

test("capture matches every pinned vector", () => {
  for (const vector of captureContract().capture_vectors) {
    const hwcap = vector.hwcap === null ? null : BigInt(vector.hwcap);
    const derived = deriveProcessorCapabilities(
      MACHINES.get(vector.architecture),
      vector.cpuinfo,
      hwcap,
    );
    assert.deepEqual(derived, vector.expected_capabilities, vector.name);
  }
});

test("auxv parsing reads hwcap and stops at the terminator", () => {
  const auxv = Buffer.alloc(48);
  auxv.writeBigUInt64LE(6n, 0);
  auxv.writeBigUInt64LE(4096n, 8);
  auxv.writeBigUInt64LE(16n, 16);
  auxv.writeBigUInt64LE(0b1010n, 24);
  assert.equal(parseAuxvHwcap(auxv), 0b1010n);
  assert.equal(parseAuxvHwcap(auxv.subarray(0, 16)), null);
  assert.equal(parseAuxvHwcap(Buffer.alloc(0)), null);
  assert.equal(parseAuxvHwcap(Buffer.from([1, 2, 3])), null);
});

test("unknown flags are ignored and output is sorted unique", () => {
  const derived = deriveProcessorCapabilities(
    "x86_64",
    "flags\t: futureflag avx2 avx2 unknownflag\n",
    null,
  );
  assert.deepEqual(derived, ["processor.feature.avx2"]);
});

test("live capture is safe on every host", () => {
  const captured = captureProcessorCapabilities();
  assert.deepEqual(captured, [...new Set(captured)].sort());
  assert.ok(captured.every((value) => value.startsWith("processor.")));
  assert.ok(captured.length <= 64);
  if (os.platform() === "linux" && ["x64", "arm64"].includes(os.arch())) {
    assert.ok(captured.length > 0);
  }
});
