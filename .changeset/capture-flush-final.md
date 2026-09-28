---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

`capture.flush` takes a kind and a deadline, the daemon no longer cuts a flush at 10 s,
`capture.status` reports `pending_bytes`, a lost lease pauses shipping instead of ending it, and
another platform's dependency tree stays on the chain.

`capture.flush` now carries `CaptureFlushArgs { kind, deadline_ms }` at the same field
(`captureFlush`, 29). `kind` is `CaptureFlushKind.SUSPEND` or `CaptureFlushKind.FINAL`, and
`UNSPECIFIED` reads as `SUSPEND`, so an older client that sends an empty message gets what it
got before. A suspend flush is unchanged: it returns once every capture ahead of a bulk upload is
registered. A final flush snaps the small class and forces a bulk snap, which a scheduled bulk
build in progress yields to. It then ships until nothing is pending, bulk included, or until a
fence, a chain conflict, or the caller's `deadlineMs`. With no deadline only the process ending
stops it. The daemon's own SIGTERM, SIGINT, `runtime.gracefulShutdown` and harness-exit flushes
are final flushes with no deadline. `sealantctl capture flush [--final] [--deadline 15m]` sends
the command.

The daemon used to clamp every flush's deadline to its shutdown grace, 10 s and never set at
boot. A flush now gets exactly the deadline it was sent. A suspend flush sent without one is
still bounded by the grace, which `SEALANT_SHUTDOWN_GRACE_MS` (boot) and
`sealantd serve --shutdown-grace-ms` now set.

`CaptureStatusReport` gains `pendingBytes` (field 14): the bytes staged on the executor's disk
that no upload has taken yet, each object counted once. It is `0` from an older daemon.

A 409 `lease-lost` from the session channel was read as a wrong parent, a chain conflict, and a
final flush stopped on it with the captures still staged. It is now a lost lease: the shipper
pauses, asks again after 1 s (doubling, 30 s at most), and keeps everything staged. A 409 that
names another `live_epoch` is still a fence.

An executor that continued a head whose bulk section was built on another platform (answered
`"pending"` by `plan.get`) dropped that section at its next capture, so the platform that built
it could never restore it. Manifests now carry such sections in `sections.other_bulk`, keyed by
platform, through every capture. The executor's own bulk snap fills `bulk` beside them, and a
registrar answers `other_bulk[platform]` to an executor of that platform. The field is absent
when empty, so existing manifests encode byte for byte as before.
