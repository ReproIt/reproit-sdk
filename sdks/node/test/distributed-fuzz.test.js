import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  FUZZ_CONTEXT_HTTP_HEADER,
  FUZZ_CONTEXT_QUEUE_METADATA,
  FUZZ_PARENT_HTTP_HEADER,
  FUZZ_PARENT_QUEUE_METADATA,
  FuzzContextError,
  FuzzContextValidator,
  extractHttpFuzzContext,
  extractQueueFuzzContext,
  propagateQueueFuzzContext,
} from "../src/public.js";
import { runWithFuzzContext } from "../src/distributed-fuzz.js";

const VECTOR = JSON.parse(readFileSync(
  new URL("../../../conformance/distributed-fuzz-context-vectors.json", import.meta.url),
  "utf8",
));

test("shared fuzz context propagates over HTTP and queue metadata", () => {
  const validator = new FuzzContextValidator({
    projectId: VECTOR.expected.project_id,
    verificationKey: VECTOR.verification_key,
  });
  const context = extractHttpFuzzContext({
    [FUZZ_CONTEXT_HTTP_HEADER]: VECTOR.encoded_context,
    [FUZZ_PARENT_HTTP_HEADER]: VECTOR.parent_operation_id,
  }, validator, VECTOR.now);
  assert.equal(context.campaignId, VECTOR.expected.campaign_id);
  assert.equal(context.caseId, VECTOR.expected.case_id);
  assert.equal(context.contextDigest, VECTOR.expected.context_digest);

  const metadata = {};
  runWithFuzzContext(context, () => propagateQueueFuzzContext(metadata));
  assert.deepEqual(metadata, {
    [FUZZ_CONTEXT_QUEUE_METADATA]: VECTOR.encoded_context,
    [FUZZ_PARENT_QUEUE_METADATA]: VECTOR.parent_operation_id,
  });
  assert.deepEqual(
    extractQueueFuzzContext(metadata, validator, VECTOR.now),
    context,
  );
});

test("fuzz context rejects tampering, wrong scope, and expiry", () => {
  const validator = new FuzzContextValidator({
    projectId: VECTOR.expected.project_id,
    verificationKey: VECTOR.verification_key,
  });
  const suffix = VECTOR.encoded_context.endsWith("A") ? "B" : "A";
  const tampered = VECTOR.encoded_context.slice(0, -1) + suffix;
  assert.throws(() => validator.validate(tampered, VECTOR.now), FuzzContextError);
  assert.throws(
    () => validator.validate(VECTOR.encoded_context, "2026-08-30T00:00:00.000Z"),
    FuzzContextError,
  );
  const wrongScope = new FuzzContextValidator({
    projectId: "prj_01890f3e-7b21-7cc0-8a1b-123456789abc",
    verificationKey: VECTOR.verification_key,
  });
  assert.throws(
    () => wrongScope.validate(VECTOR.encoded_context, VECTOR.now),
    FuzzContextError,
  );
});
