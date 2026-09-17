# Orders capture example

The [orders application](../crates/reproit-sdk-rust-axum/examples/orders.rs) accepts a JSON order
at `POST /orders`. It calculates the total in cents. It uses the current Rust SDK and Axum adapter
from this repository. It binds only to `127.0.0.1:3000`.

The test order has three units at 30,000 cents each. The correct total is 90,000 cents.
The defect calculates this total in a 16-bit integer and returns HTTP 500. The fixed calculation
converts both operands to 32-bit integers before multiplication.

## Verify the application locally

From the repository root, run:

```sh
cargo test --locked -p reproit-sdk-rust-axum --example orders
```

The test exercises the HTTP route. It checks the large total, the maximum accepted order, and
invalid orders. To restore the defect, replace the body of `total_cents` with:

```rust
order.quantity.checked_mul(order.unit_price_cents).map(u32::from)
```

Run the test again. It must fail because the response is HTTP 500 instead of HTTP 200.
Restore the original calculation and run the test again. It must pass.

These local checks have passed, including the deliberate defect check. They do not prove managed
capture, replay, debugger attachment, or a retained Repro check.

## Requirements for the managed run

Use a native Linux host with SDK capture support. The automatic capture provider does not yet
support macOS or Windows. Use an authorized hosted test service and a release of this SDK source
bound to that service. The source constants in `official_managed.rs` are release placeholders.
An unbound build stops with `CONFIG_CONFLICT`. Do not replace the signer with a fixture key or
disable validation.

The source CLI also needs its public OAuth authority and client ID. Set `REPROIT_AUTHORITY` and
`REPROIT_CLI_CLIENT_ID` together, then run `reproit login`. These values are public client metadata,
not a client secret. Keep `REPROIT_MANAGED_PROJECT_TOKEN` in the deployment secret store.

The application reads `.reproit/project.toml` from its working directory. It also reads
`ORDERS_REPOSITORY_ID` and `ORDERS_SOURCE_REVISION`. Set these to the registered repository ID and
the exact Git commit used to build the running application.

## Managed workflow to verify

The following sequence is pending hosted access and release configuration. It is not a record
of a completed capture.

1. Commit the defect in an authorized test checkout that the hosted worker can fetch.
2. Log in with the current source CLI. Connect the checkout to its registered Rust service:

   ```sh
   reproit init --sdk rust --service-path . -- \
     cargo run --locked -p reproit-sdk-rust-axum --example orders
   ```

3. Set the application metadata and project token through the deployment environment. Start the
   application with the same Cargo command.
4. Send the failed order:

   ```sh
   curl --max-time 10 --include \
     --header 'content-type: application/json' \
     --data '{"quantity":3,"unit_price_cents":30000}' \
     http://127.0.0.1:3000/orders
   ```

5. Run `reproit list`. Record the Repro ID only after the service verifies replay.
6. Run `reproit debug "$REPRO_ID"`. Attach the debugger using the displayed instructions and
   inspect the failed multiplication. Finish the debugger session.
7. Restore the fixed calculation. Run `reproit check "$REPRO_ID"` and require `PASS`.
8. Run `reproit keep "$REPRO_ID"`. Confirm that the tracked reference exists, then run
   `reproit check` and require `PASS`.
9. Restore the defect. Run `reproit check` and require `REGRESSION` with a failing exit status.
10. Restore the fix. Run `reproit check` and require `PASS`. Commit the fix and retained reference.

## Current evidence and blockers

- The local HTTP test passes with the fixed calculation and fails with the restored defect.
- `./tools/test.sh` passes on macOS. The script includes formatting, strict Rust lint checks,
  and the Rust, Python, Go, Node.js, and .NET checks. The Node native addon check is skipped when
  no addon is supplied. The macOS result does not cover native Linux managed capture.
- A source CLI initialization attempt returned `AUTHENTICATION_REQUIRED`.
- Neither inspected browser had an authenticated hosted session.
- The SDK source has unbound official service and signer constants.
- No managed Repro ID, debugger session, retained reference, or managed check verdict has been
  obtained. These remain required before the full workflow is complete.
