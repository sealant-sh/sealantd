---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

The orphan reaper now reaps only pids the daemon did not spawn. sealantd runs as PID 1 / child subreaper, and its reaper peeked every waitable child and reaped whatever the process registry did not list — so the capture engine's blocking `git` children (`rev-list`, `pack-objects`, `index-pack`, and since 0.15.1 `head_tree` and `stored_tips`), the PTY/pipe session leaders and the boot helpers, none of which were registry-owned, could be reaped mid-sweep and their own `wait()` failed with `ECHILD`: "No child process (os error 10)". A `capture.flush` that landed on the same SIGCHLD as the harness command's exit was refused that way (Mend 0.27.3's amd64 acceptance; reproduced in 1 of 8 runs on a 2-CPU daemon). Ownership now lives in a process-wide spawned-pid gate (`sealant-process/src/spawn.rs`) that every daemon-internal spawn goes through and the reaper holds for a whole sweep; a pid is released the moment its spawner has reaped it. Adopted orphans are still reaped exactly as before.
