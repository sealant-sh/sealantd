---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Capture store fixes from the first real cluster session (daemon-only; the packages ride the release
train). Tracked always wins: the workspace-class sweep no longer removes `.git/index` when the plan
does not carry one (a control-plane base has an empty workspace class), and the worktree tree is
seeded from `HEAD` when no index is on disk, so a tracked file that matches `.gitignore` (`core.*`
against `tooling/core.json`) stays in the tree instead of showing as deleted. The seed after a
materialize records only what the chain holds (refs, `HEAD`, reflog), not freshly written index and
worktree trees, so the next pack carries every subtree the disk differs by (was `fatal: unable to
read tree` on the next capture). An unchanged `auto` snap no longer deletes staged objects a queued
capture still lists (was a ship loop stuck on `upload …/trees/<sha>: no GET url in plan` behind a
long bulk upload); a snap coalescing a queued capture of the other class carries its dir objects.
The shipper mints PUT URLs in batches of 500 through one `upload.urls` call instead of one call per
object, and `.rev` files `git index-pack` leaves beside packs are removed.
