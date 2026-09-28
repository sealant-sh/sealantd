---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The eighth end-to-end run's daemon findings (F1, F5).

- **No pipe deadlock with a git the capture feeds (F1).** `git cat-file --batch-check` and `git
  rev-list --stdin` got their whole input before their answer was read: once the answers filled
  the stdout pipe, git stopped reading and both sides waited for good. With 8 KiB pipes (root
  over `fs.pipe-user-pages-soft`) 1,349 cached raw-tree blobs were enough, and no capture was
  taken after the first for 17 minutes. Every git the capture feeds on stdin is now fed from a
  thread of its own while its stdout and stderr are read (`GatedChild::communicate`).
- **A step past its bound is reported: `CaptureStatusReport.overdue` (field 31).** `step`,
  `started_unix_ms`, `running_ms`, `bound_ms`, while a snap (600 s) or a git it waits on (120 s)
  runs past its bound; absent otherwise and from an older daemon. An observation, not a
  failure. Mend reads it beside `incomplete_reason` and `snaps`: a running session whose capture
  has an `overdue` step is not idle.
- **A git of the capture is killed at its limit** (`SEALANT_CAPTURE_GIT_LIMIT_SECS`, 900): the
  snap fails, `snaps` says so (`killed`), and it is taken again. The kill never signals a reused
  pid (it is taken before the child is reaped), a killed git's scratch index lock is removed by
  the next snap, and a git that writes the repository in place (a restore) is never killed.
- **Tracked↔bulk hardlinks survive a recovery boot (F5).** A bulk name was looked up under the
  device number the dead daemon's index recorded, and a restarted container's overlay has
  another one: every link was dropped without being deferred, and the chain sealed without
  them. A bulk name is now matched by the inode it is on disk, and a final flush whose small
  snap depends on the bulk class snaps it again after the final bulk snap, staged or not (which
  also covers a lost bulk index).
