---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Five findings of the second Docker end to end (daemon-only; no wire change).

- The reply to a final `capture.flush` reaches its caller. In Docker, Core reaches the control
  socket through `docker exec … socat`, and the final flush's sweep of the PID namespace stopped
  that `socat`, so every stop saw "connection closed". The sweep now spares the process at the
  far end of a live control connection (`SO_PEERCRED`) and its ancestors, unless sealantd
  started or adopted it.
- The workspace's own Docker containers stop before the processes, then are checked again: a
  process streaming a container's output into the worktree (`docker logs -f > file`) no longer
  loses the tail, and a container a process starts on its way out is stopped.
- Nothing snaps on a schedule once a final flush stopped every writer, and a preempted scheduled
  bulk build no longer resumes after the forced one. `capture.status` reports `complete: false`
  (`pending`) while a bulk capture is being built after the final one.
- A restore keeps the directory mtimes that linking a bulk name onto a tracked inode moved:
  `node_modules` and a pnpm `file:` package's directories.
- The paths a materialize removes are logged at debug. On a fresh executor they are
  `git init`'s template files, never work product (see the capture README).
