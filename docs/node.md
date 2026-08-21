# Node.js SDK

## Install

Install the released package archive from a local release bundle or an internal package source:

```sh
npm install ./reproit-sdk-1.0.0.tgz
```

Import `@reproit/sdk/http` only when you need its Node.js HTTP adapter. The base package does not
require a web framework.

## Integrate

Create `OfficialManagedProject` from the reviewed project binding and exact source revision. Start
one operation for each accepted unit of work. Record inputs and dependency results. Discard
successful operations. Submit a failed operation only after its World closure is complete.

Source checkouts contain sentinel managed bindings. They reject official operation setup with
`CONFIG_CONFLICT`. Use an official release package for a real managed capture.

## Verify

```sh
./tools/with-core.sh sh -c 'cd sdks/node && npm test'
```
