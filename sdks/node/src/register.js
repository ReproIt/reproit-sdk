import fs from "node:fs";

import {
  acquireRuntimeObservationAdapters,
  runtimeObservationAdapterStateForTest,
} from "./runtime-observation-adapters.js";

const CAPTURE_PROBE_ENVIRONMENT = "REPROIT_INTERNAL_CAPTURE_PROBE";
const CAPTURE_PROBE_FORMAT = "reproit.capture-probe.v1";
const CAPTURE_PROBE_CLASSES = [
  "clock",
  "database",
  "environment",
  "filesystem",
  "outbound-http",
  "queue",
  "randomness",
];

// Keep one adapter lease for the lifetime of this module and process.
const releaseProcessLease = acquireRuntimeObservationAdapters();
void releaseProcessLease;

const captureProbeNonce = process.env[CAPTURE_PROBE_ENVIRONMENT];
if (captureProbeNonce !== undefined) {
  const state = runtimeObservationAdapterStateForTest();
  const valid = /^[0-9a-f]{64}$/u.test(captureProbeNonce)
    && state.leases === 1
    && state.classes.length === CAPTURE_PROBE_CLASSES.length
    && state.classes.every((value, index) => value === CAPTURE_PROBE_CLASSES[index]);
  if (!valid) process.exit(1);
  const proof = `${CAPTURE_PROBE_FORMAT}:nodejs:${captureProbeNonce}\n`;
  try {
    fs.writeSync(process.stdout.fd, proof, null, "utf8");
  } catch {
    process.exit(1);
  }
  process.exit(0);
}
