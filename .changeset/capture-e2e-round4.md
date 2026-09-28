---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Three findings of the fourth Docker end to end (daemon-only; no wire change).

- A session's first executor gets the fast repeat final flush. Its `pnpm install` runs after
  sealantd boots, so there was no bulk directory at boot and the bulk class polled for the
  executor's life: every final flush after a complete one walked the dependency tree again
  (~2.5 s; a Stop took ~15 s, not 6–7 s). The bulk class is watched with no bulk directory yet,
  and one made later gets its watches then, within the budget (past it, the bulk class polls). A
  directory too long to name to `inotify_add_watch` is watched through its opened descriptor
  (`/proc/self/fd/<fd>`) instead of making its class poll.
- A suspend flush after a complete final flush stages nothing. Mend's Stop sent two after
  `sealantctl capture flush --final`; each staged a `suspend` capture of the same tree, the final
  flush after them snapped nothing and sealed nothing, and the head read `suspend`. Over the disk
  the final flush captured, a suspend flush is a status read. Anything staged after the final
  capture all the same (a turn boundary) turns `complete` false (`pending`), and the next final
  flush seals the chain with a final capture before it says `complete`.
- A failing snap names what it did and where: `write /…/.sealantd/capture/index/last.tmp: No
  space left on device (os error 28)`, not the bare `No space left on device (os error 28)`, in
  `snaps[].last_snap_error` and the flush's error. A final flush whose small snap failed takes no
  bulk snap (it is incomplete whatever that does; each one on a kept executor walked the
  dependency tree for 2.4 s more).
