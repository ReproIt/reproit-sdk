# Platform architecture

The SDK does not need one operating-system monolith. It needs one portable core
and a small native provider for each host family.

The portable core owns these rules:

- operation state and bounds
- canonical records and content digests
- subject and World closure validation
- engine ABI validation
- encryption, delivery, and cleanup

A native provider owns only facts that the portable core cannot obtain through a
language runtime:

- the operating system, process architecture, and runtime ABI
- loaded native module paths and stable file identity
- process-visible processor capabilities
- native-effect coverage for automatic capture
- private workload-state storage

The provider must return bounded, typed evidence. It must not return application
payload bytes. If it cannot prove that its evidence is complete, the SDK keeps the
operation local.

## Native coverage authority

The application process is not the native coverage authority on macOS or Windows.
The portable SDK communicates with one authenticated host service. That service
owns the operating-system event source and returns bounded coverage evidence. The
portable core validates the evidence and keeps the capture local after any gap,
overflow, restart, or identity mismatch.

On macOS, the host service is a signed Endpoint Security system extension. Apple
requires the Endpoint Security entitlement, root execution, and user approval for
Full Disk Access. The SDK package must not contain these deployment privileges.

On Windows, the host service controls the required ETW kernel sessions and checks
the event and buffer loss counters before it closes coverage. Use a file-system
minifilter or Windows Filtering Platform callout only when the required effect is
not observable through the selected system providers. These drivers are host
components. They are not language SDK components.

## Current native engine targets

The canonical engine ABI lists the package targets. Package loaders validate that
contract before they load an engine.

| Target | Engine | Host descriptor | Module discovery | Native coverage |
| --- | --- | --- | --- | --- |
| Linux ARM64 | supported | supported | supported | supported |
| Linux x86_64 | supported | supported | supported | supported |
| macOS ARM64 | supported | supported | supported | provider required |
| Windows x86_64 | supported | supported | supported | provider required |
| FreeBSD ARM64 | not packaged | supported | supported | provider required |

The macOS and Windows engines fail closed for automatic capture until their native
coverage providers exist. The engine and package loader can still run on those
hosts. Subject packaging also requires a debugger artifact that matches the host
binary format. Native Windows PDB files use the Core `native-pdb` protocol value.
An SDK must not label a native PDB as a portable PDB.

The shared BSD module provider uses the bounded `dl_iterate_phdr` contract. It has
native FreeBSD ARM64 build, lint, and running-subject packaging coverage. The same
provider has compile coverage for NetBSD x86_64 and OpenBSD x86_64. FreeBSD does
not become a supported release target until it also has a coverage provider, a
native release package, and a matching replay worker.

BSD is an extension target, not a special architecture. Adding another BSD must
not change the portable engine or language operation model.

## Capture and replay compatibility

Capture metadata must bind these values:

```text
operating system + architecture + runtime ABI + processor capabilities
```

Replay admission must select a worker that satisfies the captured values. A Linux
worker cannot claim that it reproduces a macOS, Windows, or BSD native process.
Cross-operating-system replay is valid only for a subject format whose runtime
contract explicitly proves that portability.

## Adding a platform

1. Add the platform to the canonical engine ABI and release target catalog.
2. Implement the narrow native provider operations.
3. Add the debugger-artifact kind to Core when the format is new.
4. Build and test the engine on the matching native host.
5. Run subject packaging and native coverage negative controls on that host.
6. Add a replay worker with the same operating system and architecture.
7. Enable capture only after every completeness check passes.

Language SDKs may contain a small bootstrap map that locates the shared engine.
They must derive capture facts from the shared platform contract or validate their
generated constants against it. They must not contain separate capture policy.
