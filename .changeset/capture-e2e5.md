---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

The fifth Docker end-to-end run's daemon findings.

- **The shutdown's final flush has a deadline: `SEALANT_SHUTDOWN_FINAL_DEADLINE_MS`.** With the
  object store down, the `SIGTERM` final flush retried forever: the executor ran until the
  platform's stop timeout killed it, and the exit-75 path ("keep my disk, recover it") was never
  reached. When the variable is set, a shutdown's final flush (`SIGTERM`, `SIGINT`,
  `runtime.gracefulShutdown`) takes at most that many milliseconds from the shutdown. That
  includes waiting for a final flush already running. The daemon then exits 75 with its staging
  directory as it was. The platform should set it to its stop grace less a margin (at least 5 s).
  Unset, the flush runs until it completes, as before. `sealantd` also takes it as
  `--shutdown-final-deadline-ms`.
- **Retries spend no mint calls.** A minted PUT URL is used again until the upload of its key
  settles or the URL is five minutes old, and a multipart upload resumes under the same upload.
  Every retry used to mint again, and a store that stayed down ran the registrar's `upload.urls`
  call quota out (560 calls in three minutes). A pass that fails on a transient refusal
  (unreachable, 5xx, 429) now waits 1 s before the next one, doubling to 30 s.
- **The exit code follows the daemon's own last final flush.** A sealed, complete executor exited
  75 because its exit decision re-read the live status, which a final flush queued behind its own
  had just reset to `in-progress`. On the review-3 head, a class that polls also made every final
  flush answer `changed`, so a daemon whose bulk class polled could never exit 0. A final flush
  now answers complete when its own snaps (taken after every writer stopped) captured every class,
  a polled one included. `capture.status` read later reads `incomplete_reason: "unwatched"` (new
  reason code) while a class polls, since nothing vouches for it after the flush.
- **A dependency install no longer turns watching off.** A directory renamed or removed before
  its watch was added (`pnpm` unpacks into `<name>_tmp_<pid>_<n>` and renames it into place) made
  the bulk class poll for the executor's life: about 750 MB went uncaptured for minutes after
  `pnpm install`, and every repeat final flush walked the tree again. Such a directory is not a
  failure now. A directory that cannot be watched for a lasting reason has its class poll while
  the rest stays watched. It is tried again (2 s, doubling to 60 s), and once it is watched the
  class is watched again.
