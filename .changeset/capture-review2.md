---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The second adversarial review's daemon findings, and three cross-repo contracts.

- **A completed final flush is sealed on the chain.** When a final flush completes (every writer
  stopped, both classes snapped after that, everything staged registered), sealantd registers
  one more capture — the newest one's sections, `kind: final`, `n` = head + 1 — carrying
  `final_seal: {complete: true, epoch, executor}`, and reports `complete` only once that
  register is acknowledged. `executor` is `plan.get`'s new `executor` answer (the executor the
  session token was issued for), else `SEALANT_WORKSPACE_ID`. A capture staged later carries no
  seal; the next final flush seals again. A flush that returned at its deadline reads
  `incomplete_reason: "sealing"` once everything else registered, until the final flush is asked
  again (new reason code).
- **`plan.get` lists the manifest features the daemon reads**:
  `manifest_features: ["worktree_meta","symrefs","other_bulk","raw_names","final_seal"]`. A 409
  `manifest-features` is a protocol error naming the missing features.
- **Recovery boot.** `SEALANT_RECOVERY=1`, or the marker file `/.sealantd-recovery` (Core
  `docker cp`s it into a kept container before `docker start`), boots a retained executor that
  resumes its own staging and never materializes over its disk, runs no lifecycle step, dotfiles
  or harness, admits nothing, and runs the final flush when asked or on its stop (exit 0 only
  when complete, else 75; a recovery boot that cannot start exits 75).
- **No control peer is spared by the final sweep.** The relay carrying a final flush
  (`docker exec … socat`) is swept like any other process; the outcome survives it
  (`capture.status`, or the final flush asked again, answers it without a second quiesce). Only
  helpers sealantd spawned itself (the spawn gate's pids, in its process group, and their
  children there) are left running; joining sealantd's process group spares nothing.
- **Git refs are kept as bytes.** Two branch names that differ only in bytes that are not UTF-8
  no longer collapse into one (one branch's unique commit was lost); ref names, symbolic targets
  and a symbolic `HEAD` are `key_of` keys in the manifest, restored byte for byte. A dangling
  symbolic ref (`refs/remotes/origin/HEAD` → a missing branch) is kept and restored.
- **A hardlink between an ignored file and the bulk class restores as one inode.** The worktree
  metadata document gains `cross_links` (additive; format stays 1): inode groups no tracked file
  names, spanning the workspace and bulk classes, linked again after both classes restore.
