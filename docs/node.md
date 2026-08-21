# Node.js SDK

The Node.js SDK captures Backend operations from any request handler or application function.

## Install

```sh
npm install @reproit/sdk@1.0.0
```

## Start capture

```javascript
import { ReproIt } from "@reproit/sdk";

const reproit = new ReproIt(project, repositoryId, sourceRevision, captureWorld);
```

`reproit init` supplies `project`. The build supplies the repository identity and deployed Git
revision. `captureWorld` returns one `ManagedWorldCapture` for each operation.

## Wrap a request handler

```javascript
const handler = reproit.http(
  "orders.create",
  captureInput,
  classifyFailure,
  app,
);
```

The wrapper accepts a standard `(request, response)` handler. Express, Fastify, Koa adapters, and
the Node.js HTTP server can delegate to this function. Use `reproit.run` for another
request-response boundary. Use `reproit.runStream` or `reproit.runDeliveredWork` for those
operation types.

Dependency adapters call `operationFromRequest(request)` and then `recordDependency`. The SDK reads
`REPROIT_MANAGED_PROJECT_TOKEN` only after a complete Failure.

## Verify SDK source

```sh
./tools/with-core.sh sh -c 'cd sdks/node && npm test'
```
