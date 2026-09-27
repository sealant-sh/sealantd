---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

A resumed executor keys its bulk captures by the workspace's libc, captures incrementally, and
reports a bulk build in progress.

- The bulk platform key (`<os>-<arch>-<libc>`, on `plan.get` and on every bulk section) now names
  the workspace userland's C library, detected at run time (the musl loader, else
  `ldd --version`), the way Mend's probe does. The release daemon is a static musl binary and
  said `linux-x86_64-musl` in glibc workspaces, so every resume treated the head's dependency
  tree as another platform's and installed it again. A section an older daemon stamped `-musl`
  there costs one more install: it is kept in `other_bulk`, never dropped, and the next bulk
  capture fills `bulk` under `-gnu`.
- A restored executor learns where the head's chunks are (the packs the registered head names,
  from the materializer's pack cache), so its next capture reads and uploads only what changed;
  it used to read and upload the whole dependency tree again after every resume.
- `capture.status` gains `bulk_building` (field 25 of `CaptureStatusReport`), and
  `pending_bytes` counts what a bulk build in progress has staged: a drain read "nothing
  pending" while hundreds of megabytes were staged by a build not yet queued.
