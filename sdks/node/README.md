# Repro It SDK for Node.js

Install the official package archive from your Repro It release bundle:

```sh
npm install ./reproit-sdk-1.0.0.tgz
```

Use `OfficialManagedProject` for the reviewed project and source revision. Start one operation for
each accepted unit of work. Record its inputs and observed dependencies. Mark successful operations
as successful. Submit a failure only after its World closure is complete.

The base package is framework-neutral. Import `@reproit/sdk/http` for the optional Node.js HTTP
adapter. The SDK does not require a sidecar, container engine, orchestrator, or container socket.

See the [Node.js guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/node.md) for source
verification and release behavior.
