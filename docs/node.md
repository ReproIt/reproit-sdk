# Node.js SDK

Use the Node.js SDK at one supported Backend operation boundary.

## Install

```sh
npm install @reproit/sdk@1.0.0
```

Use `runOperation`, `runStreamOperation`, or `runDeliveredWork` with the framework-neutral SDK
core. Backend v1.0 does not publish a Node.js framework adapter.

The SDK sends only complete failed operations to managed Repro It Cloud. It keeps successful,
incomplete, unsupported, and resource-limited operations local.

## Verify SDK source

```sh
./tools/with-core.sh sh -c 'cd sdks/node && npm test'
```
