---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The fourth adversarial review's daemon findings (#2, #3, #4, #7, #8, #11), and the executor side
of cross-repo decisions 11 and 12.

- **The working tree is read from disk, not from the user's index shortcuts (#2).** The scratch
  index a snap stages into drops `assume-unchanged`, and `skip-worktree` for every path on disk,
  so an edit behind either is captured (it restored the committed bytes, or never completed).
  Every git the capture runs gets `core.ignorecase=false`, `core.fsmonitor=false`,
  `core.untrackedCache=false`, `core.checkStat=default` and `core.trustctime=true` through
  `GIT_CONFIG_COUNT`: a distinct `A` beside a tracked `a` is captured on a case-sensitive disk
  whatever the repository's `ignorecase`. The scratch copy keeps the real index's mtime. The
  user's `.git/index` and `.git/config` are never written.
- **Short object ids in operation state (#3).** Every run of 4–64 hex digits in `FETCH_HEAD`,
  `ORIG_HEAD`, the pending pseudo-refs and the rebase/`am`/sequencer directories is resolved as
  git resolves it (`cat-file --batch-check`), and what resolves to one object is packed. What an
  operation needs to go on — each line of `MERGE_HEAD`, `CHERRY_PICK_HEAD`, `REVERT_HEAD`,
  `REBASE_HEAD`, `AUTO_MERGE`, `BISECT_HEAD`, `BISECT_EXPECTED_REV`; the operand of a todo
  list's `pick`/`reword`/`edit`/`squash`/`fixup`/`drop`/`revert`/`merge -C` lines; `onto`,
  `orig-head`, `stopped-sha` and the other single-id files — must resolve to exactly one: a
  missing or ambiguous one fails the final snap (`snapshot-failed`), never complete.
- **A store that cannot hold what a capture holds never completes (#7, decision 12).** A
  `plan.get` answer whose `manifest_features` leaves out one this build writes (`git_trees`
  above all) no longer downgrades silently: captures still ship, but every final flush answers
  `incomplete_reason: "store-fidelity"` (new reason code) and seals nothing. A re-plan takes the
  new registrar's features.
- **A captured `.git/config` is authoritative (#8).** Plan remotes seed only a base: an empty
  chain, or a capture without `.git/config`. A fresh executor no longer adds back a remote the
  user removed. `MaterializeReport::git_config` says whether a materialize restored one.
- **The final flush's sweep covers the machine on a MicroVM (#4).** `SEALANT_SWEEP_EXEMPT_FILE`
  (Core's agent: `{"version":1,"exempt":[{"pid","startTime","role","descendants"}]}`) makes a
  daemon that is not PID 1 sweep every process but its ancestors, its own helpers and the listed
  live processes (pid and start time must both match; descendants only when listed with them).
  An unreadable list is `sweep-unavailable`. A recovery boot that is not PID 1 and has no list is
  always `sweep-unavailable`: the dead daemon's orphans are the agent's, out of its descendants.
  Stopping the workspace daemon's containers through the Engine API is not undone by a restart
  policy (tested against a disposable dind).
- **The launch from the first `plan.get` (#11, decision 11).** `SEALANT_CAPTURE_LAUNCH_ID` (new)
  names the launch; the request carries `launch` (else the launch the disk last served), a plan
  answering another `executor` refuses the boot, and a disk's staging continues the chain across
  an epoch change only for the launch that staged it (`last.json` records it).
- **Refusals that pause, never adopt (Mend round 4).** `plan.get` 409 `worktree-leased` is
  `RegistrarError::WorktreeLeased` (it read as a wrong parent and failed the boot): a boot waits
  and asks again, touching nothing, and a re-plan keeps its identity. A heartbeat's `lease-lost`
  pauses the harness at once (it waited for the lease TTL). `upload.urls` and `capture.register`
  `lease-lost` pause shipping with everything staged under its epoch, as before, now tested per
  call.
