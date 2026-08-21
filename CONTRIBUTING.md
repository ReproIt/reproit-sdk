# Contributing to the Repro It SDKs

Use this guide when you change capture behavior in one or more SDK packages.

## Change an SDK

1. Confirm that `core-pin.json` names the required Core revision.
2. Change the smallest SDK surface that owns the behavior.
3. Add a regression test for success, rejection, and the affected limit.
4. Run `./tools/test.sh`.
5. Run the native conformance matrix when wire behavior, packaging, or processor capture changes.

Do not copy a schema, vector, or shared rule from Repro It Core. Change Core first, publish one
immutable Core commit, then update `core-pin.json` and the Rust Git dependencies together.

Do not add a vendored dependency directory. Lock files and exact dependency versions provide the
reproducible dependency identity.

## Package boundaries

Production packages expose the official managed entry and operation-capture API. Memory sinks,
loopback transports, fixture keys, and synthetic subjects must remain test-only.

Do not add a customer-selected Cloud endpoint, capture signer, managed worker route, container
socket, or orchestrator requirement to an SDK package.
