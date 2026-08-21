# Go SDK

## Install

Use the released module from a local release bundle or an internal module source. The package path
is `reproit.dev/sdk-go/reproit`.

The base package is framework-neutral. Its HTTP adapter uses the standard `net/http` interfaces.

## Integrate

Call `NewOfficialManagedProject` with the reviewed project binding and exact source revision. Start
one operation for each accepted unit of work. Record inputs and dependency results. Discard
successful operations. Submit a failed operation only after its World closure is complete.

Source checkouts contain sentinel managed bindings. They reject official operation setup with
`CONFIG_CONFLICT`. Use an official release package for a real managed capture.

## Verify

```sh
./tools/with-core.sh sh -c 'cd sdks/go && go test ./...'
```
