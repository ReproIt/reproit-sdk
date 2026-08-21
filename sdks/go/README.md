# Repro It SDK for Go

Install the official module from your Repro It release bundle or internal module source. Import the
SDK as `reproit.dev/sdk-go/reproit`.

Use `NewOfficialManagedProject` for the reviewed project and source revision. Start one operation
for each accepted unit of work. Record its inputs and observed dependencies. Mark successful
operations as successful. Submit a failure only after its World closure is complete.

The base package is framework-neutral. Its HTTP adapter uses the standard `net/http` interfaces.
The SDK does not require a sidecar, container engine, orchestrator, or container socket.

See the [Go guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/go.md) for source
verification and release behavior.
