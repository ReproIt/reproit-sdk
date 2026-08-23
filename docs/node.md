# Node.js SDK

Add Repro It to a Node.js application.

## Install

```sh
npm install @reproit/sdk@1.0.0
```

```javascript
import { ReproIt } from "@reproit/sdk";

const reproit = ReproIt.init();
const todo = await reproit.operation(
  "todos.create",
  inputBytes,
  () => createTodo(input),
);
```

Run `reproit init` before you deploy. Initialize the SDK once. Call `operation` at a top-level
application boundary. The SDK records a thrown or rejected error as the Failure. It preserves the
exact result. It does not import a web framework.

## Verify SDK source

```sh
./tools/with-core.sh sh -c 'cd sdks/node && npm test'
```
