# Repro It SDK for Node.js

Capture failed Backend operations from a Node.js application.

Install the package from the release directory that `reproit init` shows. Use
`OfficialManagedProject` during application setup. Use `runOperation` at each top-level operation
boundary.

Import `@reproit/sdk/http` for a Node.js HTTP adapter. Use the base package for streams, delivered
work, other frameworks, and direct operation capture.

Read the [Node.js integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/node.md).
