---
"@sealant/runtime-protocol": minor
---

A workspace boot is now one trace. A container boot records `sealantd.boot` from the process's start, as a child of `SEALANT_TRACEPARENT` when set. A host-vm boot records the runner's `sealantd.vm.launch` and the guest's `sealantd.vm.boot`, under the `telemetry.traceparent` staged in `boot-env.json`. Each stage is a child span carrying `sealant.boot.stage`: provisioning (`clone`, `mount` or `restore`), `healthy`, `control_ready` and `harness_started`, plus the guest's `disk_layout` and `boot_config`. An error during the boot is linked to its trace. The VM runner and the egress proxy export too, under the plain `SENTRY_*` variables. The runner passes the guest its DSN, environment and release, from the staged `telemetry` or its own environment.
