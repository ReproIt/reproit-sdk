# Node.js SDK

Use the framework-neutral operation boundary for request-response, stream, and
delivered-work operations. A framework adapter can delegate to the same boundary.

## Install

```sh
npm install @reproit/sdk@1.0.0
```

Open one project, prepare the operation, and run the application callback:

```js
import { ManagedEngineProject, runOperation } from "@reproit/sdk";

const project = ManagedEngineProject.open({
  projectToml,
  buildRepositoryId,
  sourceRevision,
  projectTokenProvider: loadProjectToken,
});
const preparation = {
  begin: beginPayload,
  inputs: inputPayloads,
  completion: "return",
};
const result = runOperation(
  project,
  preparation,
  (operation) => applicationCall(),
  classifyFailure,
);
```

Use `return` for request-response, `stream-end` for stream, and `acknowledgment`
or `task-end` for delivered work.

The Node.js layer owns subject discovery, operation context, and Failure translation.
The packaged shared engine owns candidate policy, World closure, encryption,
delivery, and cleanup. A successful operation is deleted locally.

## Verify SDK source

```sh
./tools/with-core.sh sh -c 'cd sdks/node && npm test'
```
