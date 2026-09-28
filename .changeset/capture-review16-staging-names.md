---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

A restore never consumes a user file named like its staging file (review 16 #2). The delta
restore's hardlink split copied a file through the fixed name `.<name>.capture-apart` and the
file writer through `.<name>.capture-tmp`, both opened with truncation: a captured user file of
that name was overwritten and renamed onto the restored file, and the restore reported success
without it. Staging files are now created exclusively (`O_EXCL`) under a fresh name, never over
an existing one, and only a staging file the restore created is removed on a failure. A sealed
final capture restored whole also fails when any file a class promised is missing afterwards.
