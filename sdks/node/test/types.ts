import {
  Sdk,
  type CandidateSink,
  type CandidateStart,
  type Json,
  type OperationPreparation,
  runDeliveredWork,
  runPreparedOperation,
  runStreamOperation,
} from "../src/index.js";
import { wrapHttpHandler } from "../src/http.js";

const sink: CandidateSink = {
  processingModes: new Set<"managed">(["managed"]),
  queuedBytes: 0,
  trySend: () => true,
};
const sdk = new Sdk(sink);
const payload: { [key: string]: Json } = { format: "test" };
const start: CandidateStart = {
  captureId: "capture",
  deployment: { processing_mode: "managed" },
  operationId: "operation",
  worldId: "world",
};

sdk.begin(start, payload);
sdk.recordInput(start.operationId, payload);
sdk.recordDependency(start.operationId, payload);
sdk.cancel(start.operationId);
sdk.abandonIncomplete(start.operationId);

const preparation: OperationPreparation = {
  begin: payload,
  dependencies: [],
  inputs: [payload],
  start,
};
runPreparedOperation(sdk, preparation, () => "result", () => payload);
runStreamOperation(sdk, preparation, () => "result", () => payload);
runDeliveredWork(sdk, preparation, () => "result", () => payload);

const handler = wrapHttpHandler(
  sdk,
  () => ({ begin: payload, inputs: [payload], start }),
  () => payload,
  () => "result",
);
const result: string = handler({}, {});
void result;
