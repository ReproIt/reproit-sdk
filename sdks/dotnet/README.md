# Repro It SDK for .NET

Use this SDK at one supported Backend operation boundary. The SDK keeps bounded
records. It sends only complete failed operations to managed Repro It Cloud.

The transport-neutral API supports request-response, ordered-stream, and
delivered-work operations. Backend v1.0 does not publish a framework adapter.

The same API works in a host process or an OCI container. It does not require a
framework, container engine, sidecar, orchestrator, or container control socket.

The SDK does not send successful or incomplete operations. A capture failure or
Cloud outage does not change application behavior. The official managed entry
uses the Cloud origin and signer that the released package contains.

Install release packages from local files or an internal package source. The
package gate verifies deterministic package bytes and restores with an empty
external feed.
