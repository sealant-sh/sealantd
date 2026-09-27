---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

A final `capture.flush` stops the executor's writers before its last snaps, and says whether it
completed. Only `complete: true` means saved.

The order is now: admission closes for good (no new process, exec, session, SFTP bridge,
execution, bind or re-plan); every managed process and session is terminated (`SIGTERM`, then
`SIGKILL` after the grace) and awaited; the small and the bulk class are snapped, and both must
succeed; everything ships until nothing is pending. Before, the daemon snapped first and
terminated after, so anything a process wrote during the upload or from its `SIGTERM` handler
was lost. The SIGTERM, SIGINT, `runtime.gracefulShutdown` and harness-exit paths use the same
order.

`CaptureFlushArgs` gains `graceMs` (field 3): how long managed processes get after `SIGTERM`
before `SIGKILL`, counted inside `deadlineMs`. Absent, the daemon's shutdown grace.

`CaptureStatusReport` gains `complete` (field 15) and `incompleteReason` (field 16). `complete`
is true only after a final flush ran to the end: writers stopped, both classes snapped, nothing
pending, and the lease not fenced. Otherwise `incompleteReason` is one of `not-final`,
`processes-remain`, `snapshot-failed`, `fenced`, `conflict`, `deadline`, `ship-failed`, `pending`
or `internal`. A final flush now answers with the report whatever happened, and never as a
success while work is left: a failed bulk snap used to be logged and ignored, and a flush on an
already fenced lease used to answer as finished with captures still staged. A report from an
older daemon decodes with `complete: false`, so `pending == 0` alone must not be read as saved.

A daemon whose final flush did not complete exits with 75 (`EX_TEMPFAIL`) and keeps its staging
directory, instead of exiting 0.

A small capture staged ahead of a queued bulk capture now rewrites the queue as one journaled
step (`restage.json`), finished on the next open or snap. A crash between the two queue writes
used to leave the bulk capture naming a parent no entry held, which blocked shipping for good.

`sealantctl capture flush --final --grace 30s` sends the grace.
