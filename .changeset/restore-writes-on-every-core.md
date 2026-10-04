---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

A restore writes files on every core, up to 16. The walk of a capture's tree still makes every
directory in order. The files are then written on threads, each one staged beside its path and
renamed into place, as before. On the Docker box a boot restoring the mend project, 127,000 files
and 2.48 GB of them dependencies, spent 31-40 s in `capture head materialized`, writing those files
one after another. Copying the same tree there takes 14.8 s on one thread and 2.1 s on twelve. On a
32-core workstation the whole restore of 146,469 files went from 8.0 s to 5.0 s, and the restored
tree's `git status` is identical. `capture head materialized` now logs `elapsed_ms`.
