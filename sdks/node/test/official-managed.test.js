import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  ManagedError,
  OfficialManagedProject,
  createOfficialManagedCandidateSink,
} from "../src/index.js";
import {
  encodeBase64url,
  verificationKey,
} from "../src/managed-protocol.js";
import { ManagedTlsEndpoint } from "../src/managed-transport.js";

const SENTINELS = [
  "__REPROIT_OFFICIAL_MANAGED_HTTPS_ORIGIN_SENTINEL__",
  "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_ID_SENTINEL__",
  "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY_SENTINEL__",
];

test("workspace official managed entry fails closed", async () => {
  await assert.rejects(
    () => createOfficialManagedCandidateSink(null, {}, {}),
    (error) =>
      error instanceof ManagedError && error.code === "CONFIG_CONFLICT",
  );
});

test("workspace official project fails before project or capture use", () => {
  assert.throws(
    () => new OfficialManagedProject(null, "invalid", "invalid"),
    (error) =>
      error instanceof ManagedError && error.code === "CONFIG_CONFLICT",
  );
});

test("official bindings have one immutable materialization site", () => {
  const source = fs.readFileSync(
    new URL("../src/official-managed.js", import.meta.url),
    "utf8",
  );
  for (const sentinel of SENTINELS) {
    assert.equal(source.split(sentinel).length - 1, 1, sentinel);
  }
  assert.equal(source.includes("process.env"), false);
});

test("materialized official bindings create one fixed managed client", async () => {
  const publicKey = encodeBase64url(verificationKey(Buffer.alloc(32, 0x55)));
  const module = await materializedModule({
    origin: "https://cloud.reproit.com",
    publicKey,
    signerId: "managed-capture-release-1",
  });
  const configuration = module.officialManagedConfiguration();
  assert.equal(configuration.managedOrigin, "https://cloud.reproit.com");
  assert.equal(configuration.captureSignerId, "managed-capture-release-1");
  assert.deepEqual(
    configuration.captureSignerPublicKey,
    verificationKey(Buffer.alloc(32, 0x55)),
  );
});

test("official entry does not change caller deployment on failure", async () => {
  const publicKey = encodeBase64url(verificationKey(Buffer.alloc(32, 0x55)));
  const module = await materializedModule({
    origin: "https://cloud.reproit.com",
    publicKey,
    signerId: "managed-capture-release-1",
  });
  const deployment = { runtime_endpoint: "unchanged" };
  await assert.rejects(() =>
    module.createOfficialManagedCandidateSink(
      null,
      { projectTokenProvider() {}, serviceId: "invalid" },
      { deployment },
    ),
  );
  assert.equal(deployment.runtime_endpoint, "unchanged");
});

test("official endpoint accepts only one HTTPS origin", () => {
  assert.equal(
    ManagedTlsEndpoint.official("https://cloud.reproit.com").origin,
    "https://cloud.reproit.com",
  );
  for (const invalid of [
    "http://cloud.reproit.com",
    "https://cloud.reproit.com/path",
    "https://user@example.com",
    "https://cloud.reproit.com:8443",
  ]) {
    assert.throws(() => ManagedTlsEndpoint.official(invalid));
  }
});

async function materializedModule({ origin, publicKey, signerId }) {
  let source = fs.readFileSync(
    new URL("../src/official-managed.js", import.meta.url),
    "utf8",
  );
  for (const moduleName of [
    "managed-protocol.js",
    "managed-sink.js",
    "managed-transport.js",
  ]) {
    source = source.replace(
      `"./${moduleName}"`,
      JSON.stringify(new URL(`../src/${moduleName}`, import.meta.url).href),
    );
  }
  source = source
    .replace(SENTINELS[0], origin)
    .replace(SENTINELS[1], signerId)
    .replace(SENTINELS[2], publicKey);
  const encoded = Buffer.from(source).toString("base64");
  return import(`data:text/javascript;base64,${encoded}`);
}
