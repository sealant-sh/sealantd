# sealantd fuzz targets

libFuzzer targets for the untrusted control-protocol decoders (plan §22 Phase 7). These build under
nightly only and are detached from the main workspace (`stable cargo build --workspace` skips them).

The same surfaces are covered by an in-repo seeded robustness test that runs in the normal gate:
`sealant-protocol` → `decoders_never_panic_on_arbitrary_input`.

## Run

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run decode_client -- -max_total_time=60
cargo +nightly fuzz run decode_server -- -max_total_time=60
cargo +nightly fuzz run decode_event  -- -max_total_time=60
```

A target is "clean for a budget" when it runs the time budget with no crash/leak/timeout.

`.github/workflows/fuzz.yml` runs each target for 60 seconds every night and uploads the input of a
crash. `pnpm verify formal` runs a 20-second pass of the targets a change reaches
(`--fuzz-seconds` to change it).
