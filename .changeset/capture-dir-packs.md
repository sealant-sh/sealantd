---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Dir packs, uploads in flight, and no work product lost (daemon-only; the packages ride the
release train, and `capture.status`'s `refused` changes meaning).

On alpha a pnpm `node_modules` of about 800 MB was 20,878 objects, about 20,860 of them dir
objects, one per directory. The shipper uploaded them one PUT at a time, about 70 ms each, so the
capture took 24 minutes, and a restore would have fetched them one GET at a time. When the
registrar's `plan.get` answers `manifest_format: 2`, a capture's dir objects now travel in dir
packs: the CDC pack container, keyed `…/packs/<sha256>`, listed in the section's new `dir_packs`,
with `root` and every `child` naming a dir object by digest. Sections carry `format` (absent = 1,
one object per directory, byte for byte what was written before). A registrar that does not
announce format 2 gets format 1, and the executor reads both, including a manifest that holds one
section of each. A later capture packs only the dir objects it changed, and a section lists at
most 16 dir packs. Objects below the multipart threshold go up eight at a time, and a materialize
fetches packs eight at a time. Measured with 6,002 directories and 20,003 files at 40 ms per
request: the first bulk capture went from 6,018 requests in 242 s to 4 requests in 0.12 s, and a
full restore went from 6,016 GETs in 242 s to 8 GETs in about a second.

A capture refused for the byte quota is no longer dropped with everything staged after it. It is
held in the queue with its staged bytes, its class is named in `capture.status`'s `refused`, and
the executor asks again after a backoff (30 s, doubling, 10 minutes at most) until the budget
allows. A held bulk class keeps snapping: the newer capture replaces the held one. A `final`
flush (SIGTERM, SIGINT, `runtime.gracefulShutdown`) also snaps the bulk class. It ships
everything with no deadline and returns only when the queue is empty or nothing can register (a
fence or a chain conflict). A daemon that restarts on its own disk no longer materializes the head
over captures it staged and did not ship, or over edits made after its last snap. The queue
resumes, and both classes are snapped.
