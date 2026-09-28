---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Opening capture never consumes a user file named like its git staging file (review 17 #2).
Adding the daemon's line to `.git/info/exclude` staged the new file through the fixed name
`.git/info/exclude.capture-tmp`, opened with truncation, and renamed it over `info/exclude`: a
user file of that name was overwritten and renamed away at the first open and again when a
restarted executor reopened a disk whose sealed capture held it, and the next final flush sealed
the disk without it. The restore's `HEAD`, `packed-refs` and pack writers had the same fixed
names (`HEAD.capture-tmp`, `packed-refs.capture-tmp`, `objects/pack/tmp-capture-<sha>.*`). All
four now stage in a file created exclusively (`O_EXCL`) under a fresh name, and only that file is
removed on a failure.
