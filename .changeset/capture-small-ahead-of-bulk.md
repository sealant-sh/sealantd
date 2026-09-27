---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

A small capture no longer waits for a bulk capture's upload, and `capture.status` gains
`pending_bulk` (daemon behaviour plus one additive wire field).

The capture chain is linear, and a bulk capture (a dependency tree) was an ordinary link in it.
On alpha a session's `pnpm install` left about 800 MB of `node_modules` in about 20k objects,
which took the shipper twenty minutes to upload. Every small capture staged after it named it as
its parent and waited behind it, so the agent's edits never registered while it uploaded:
`capture.flush` timed out or answered `pending 5`, and the checkpoints the control plane derived
read `0 files · +0 −0`. The engine now stages a small capture ahead of a queued bulk capture that
is still uploading. The small capture takes the bulk capture's place on the chain with the bulk
section it was staged on (or `"pending"`), and the bulk capture moves on top of it with the same
objects and a new manifest. The shipper uploads a bulk capture's objects without claiming it and
stops between objects when a capture is staged ahead of it or a flush is waiting. `capture.flush`
returns once every capture ahead of the bulk capture is registered, and the bulk capture keeps
uploading in the background. `capture.status` reports it in `pending` and in the new
`pending_bulk` field (`CaptureStatusReport.pendingBulk`), so a caller reads
`pending == pending_bulk` as flushed. A `final` flush still spends what is left of its deadline
on the bulk capture.

A flush also used to run its ship pass beside the worker's over the same objects. Each pass took
the PUT URLs the other had minted, the losing pass minted one key per `upload.urls` call, and the
registrar's call quota answered 429, reported as `no url for …/trees/<sha>` and never retried.
One pass runs at a time now. A 429 or 5xx from `upload.urls` is a transient failure and is
retried, a failed batch mint is retried as a batch rather than one call per key, and URLs minted
in the last five minutes are reused instead of minted again.
