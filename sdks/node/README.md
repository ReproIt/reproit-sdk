# Repro It SDK for Node.js

Use `ManagedEngineProject` and `runOperation` at a framework-neutral Backend
operation boundary. The same boundary supports request-response, stream, and
delivered-work operations. A framework adapter can delegate to it.

```sh
npm install @reproit/sdk@1.0.0
```

The Node.js layer owns subject discovery, operation context, and Failure translation.
The packaged shared engine owns candidate policy, World closure, encryption,
delivery, and cleanup. It deletes successful operations locally.

An open project automatically captures supported `http.get` and `https.get`
responses. It captures complete response streams up to 16 KiB and replays them
without live network access. Unsafe, partial, and oversized observations stay local.

Read the
[Node.js integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/node.md).
