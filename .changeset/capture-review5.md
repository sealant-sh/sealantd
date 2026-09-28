---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The fifth adversarial review's daemon findings (#2, #5, #6, #11), and the executor side of
cross-repo decisions 15 and 16.

- **A capture runs none of the user's code; a seal is written only over the disk as it is (#2,
  decision 15).** Every git the capture runs empties each filter driver the configuration defines
  (`clean`, `smudge`, `process`, `required=false`) and sets `core.hooksPath=/dev/null`: a clean
  filter that wrote a file git had already indexed changed the disk under a final flush that went
  on to seal it. A path a filter's attribute names is read as its bytes on disk (in
  `worktree_tree` too); a restore of a capture without `raw_tree` still smudges. Before staging
  the seal, the final flush settles the watcher (a fence through its event stream) and checks
  that nothing changed since its first snap; when something did it snaps every class again (three
  rounds at most), and a disk that keeps changing answers `incomplete_reason: "changed"` with no
  seal. `capture.status` reads the same predicate.
- **No user code over a store that cannot hold what a capture holds (#5, decision 16).** A
  `plan.get` whose `manifest_features` leaves out one this daemon writes refuses the boot right
  after `plan.get`, before the materialize — no dotfiles, lifecycle step, harness, exec or
  session — and the daemon exits **78** (`EX_CONFIG`, `EXIT_STORE_UNFIT`, log
  `outcome="store-unfit"`): nothing materialized, nothing ran, nothing saved. A standby's
  `capture.replan` onto such a store answers `policy-denied` with detail
  `{"reason":"store-unfit","unread":[…]}`, touching nothing. A recovery boot is not refused (it
  admits no writer); its final flush says `store-fidelity` and it exits 75.
- **A symlink is a symlink, whatever `core.symlinks` says (#6).** The capture's git runs with
  `core.symlinks=true` (and `core.safecrlf=false`): a regular file that replaced a tracked symlink
  under `core.symlinks=false` restored as a symlink to its own content. A tree path whose kind on
  disk is not the tree's is named (`Captured::changed_kind`) and fails a final snap
  (`snapshot-failed`), never silently left out of the metadata.
- **Cross-class hardlinks are only promised when they can be kept (#11).** A link names a bulk
  member only while its stat is the one the last bulk snap read; one that changed since waits for
  a small snap after a bulk snap, which a final flush takes (`snapshot-failed` while a link is
  still left out). A sealed final capture restored whole applies its links strictly: a member
  missing, not a file or holding other bytes fails the materialize (`LinkUnfulfilled`) instead of
  passing with two inodes.
