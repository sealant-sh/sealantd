---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

The orphan reaper can no longer steal a Tokio-owned child's exit status. Spawn paths (exec, sftp bridge) now register their child's pid in an owned-pid set under a shared spawn↔reap lock, and the reaper holds that lock for its whole sweep — closing the race where a fast-exiting child (e.g. `printf`) was reaped as an "adopted orphan" before its ownership was recorded, surfacing as `process.exited` with `exit_code: null` (the intermittent `binary_stdio_roundtrips_binary_unsafe_output_and_shuts_down` CI failure).
