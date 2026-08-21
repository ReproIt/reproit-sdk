# Repro It SDK for Go

Capture failed Backend operations from a Go application.

Install the module from the release directory that `reproit init` shows. Use
`NewOfficialManagedProject` during application setup. Use `RunOperation` at each top-level
operation boundary.

The HTTP adapter uses standard `net/http` types. Use the base package for streams, delivered work,
other frameworks, and direct operation capture.

Read the [Go integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/go.md).
