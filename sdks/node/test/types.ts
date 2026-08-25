import {
  type Json,
  ManagedEngineProject,
  type OperationPreparation,
  type TriggerCompletion,
  runOperation,
} from "../src/index.js";

const payload: { [key: string]: Json } = { format: "test" };
const preparation: OperationPreparation = {
  begin: payload,
  completion: "return",
  inputs: [payload],
};
const project = null as unknown as ManagedEngineProject;
if (false) {
  runOperation(
    project,
    preparation,
    (context) => {
      context.recordInput(payload);
      return context.operationId;
    },
    () => payload,
  );
}
const completion: TriggerCompletion = "return";
void completion;
