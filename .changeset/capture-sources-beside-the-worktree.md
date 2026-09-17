---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Content beside the worktree in a capture-source workspace (daemon-only; the packages ride the
release train). `plan.get` may now answer `sources`: per source a name, an absolute path, the
object key of a gzipped tar whose GET URL rides `get_urls`, the archive's `sha256`, its `bytes`
and `read_only`. The boot fetches each one, verifies the digest, and extracts it at that path
before the control socket binds.

A capture-source workspace mounts nothing from the host — the executor materialises the worktree's
head capture on its own disk — so a control plane had no way to put a directory beside the
repository. This is how Mend's organization folders and reference repositories reach one. Three
rules: a path inside the worktree (or one the worktree sits under) fails the boot, because content
there would be listed by the next capture and shipped into the store as the session's own work; a
source is a copy and never travels back, with `read_only` additionally taking the writable bit off
the tree; and the archive's sha256 is the content stamp, so a re-materialize re-extracts only what
changed. One source failing costs that directory and not the session — a fetch, digest or
extraction failure is logged and skipped, extraction runs in the staging scratch directory and is
renamed into place, and an archive past 64 MiB is skipped.

`capture.replan` lays down the sources of the worktree it is assigned, because a standby executor
boots under a placeholder worktree and only then learns whose session it is. A registrar that
answers no `sources` is unchanged in every respect.
