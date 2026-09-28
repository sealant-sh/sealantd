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
was lost. Writers outside the managed process groups are stopped the same way: every process
in the PID namespace when sealantd is its PID 1 (a container), otherwise every descendant of
sealantd, the child subreaper (a MicroVM), so a process that `setsid`'d or double-forked out of
its group no longer writes past the last snap. Every running container of the workspace's own
Docker daemon is stopped too (`SEALANT_WORKSPACE_DOCKER_HOST`, or the `DOCKER_HOST` Core sets for
Docker in the MicroVM and the dind sidecars; a host daemon is never touched). The SIGTERM,
SIGINT, `runtime.gracefulShutdown` and harness-exit paths use the same order.

`CaptureFlushArgs` gains `graceMs` (field 3): how long managed processes get after `SIGTERM`
before `SIGKILL`, counted inside `deadlineMs`. Absent, the daemon's shutdown grace.

`CaptureStatusReport` gains `complete` (field 15) and `incompleteReason` (field 16). `complete`
is true only after a final flush ran to the end: writers stopped, both classes snapped, nothing
pending, and the lease not fenced. Otherwise `incompleteReason` is one of `not-final`,
`processes-remain`, `sweep-unavailable`, `snapshot-failed`, `unreadable`, `fenced`, `conflict`,
`deadline`, `ship-failed`, `pending` or `internal`. A final flush that returned at its deadline
ends nothing: admission stays closed, the writers stay stopped, the upload goes on, and
`complete` turns true once it is done; asked again, the flush neither stops the writers again nor
takes a new capture of an unchanged disk. A final flush now answers with the report whatever happened, and never as a
success while work is left: a failed bulk snap used to be logged and ignored, and a flush on an
already fenced lease used to answer as finished with captures still staged. A report from an
older daemon decodes with `complete: false`, so `pending == 0` alone must not be read as saved.

When the daemon's own way out (SIGTERM, SIGINT, `runtime.gracefulShutdown`, the harness exiting)
ends with its final flush incomplete, it exits with 75 (`EX_TEMPFAIL`) and keeps its staging
directory, instead of exiting 0. A daemon that is not a child subreaper (and not PID 1 of its
PID namespace) answers every final flush `sweep-unavailable`.

A small capture staged ahead of a queued bulk capture now rewrites the queue as one journaled
step (`restage.json`), finished on the next open or snap. A crash between the two queue writes
used to leave the bulk capture naming a parent no entry held, which blocked shipping for good.

`sealantctl capture flush --final --grace 30s` sends the grace.
