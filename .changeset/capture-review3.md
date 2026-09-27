---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The third adversarial review's daemon findings, and the executor side of cross-repo decisions
5–8.

- **Capture starts before user code (decision 8).** The capture engine starts right after the
  head is materialized, before dotfiles, lifecycle setup/startup steps and the harness (setup
  could write for hours with no capture running). Every exit after that point runs the final
  flush and exits 75 when it is incomplete: a failed dotfiles apply, WSS frontend, lifecycle step
  or harness launch included.
- **`complete` means current (decision 7).** `capture.status` and the final flush's answer (the
  same report) say `complete` only while the disk is as the last final flush captured it. Any
  later change signal or a watcher overflow reads `incomplete_reason: "changed"` (new reason
  code) until a final flush is asked again.
- **The seal names the launch (decision 5).** `final_seal.executor` is `plan.get`'s `executor`
  and nothing else. `SEALANT_WORKSPACE_ID` is no longer read for it, and a plan with no
  `executor` gets no seal. A re-plan takes the new plan's executor.
- **Refused keys are never written again (decision 6).** Object keys gain a key generation,
  `captures/<worktree>/<epoch>/g<n>/{packs,trees,manifests}/<sha256>`, kept per worktree and
  epoch in staging. Every register refusal rebuilds the capture from disk under the next
  generation, so the same bytes go up under a new key. The shipper no longer puts the refused
  keys again, and a rebuild carries none of them. Keys without the segment still read.
- **`git_trees` manifest feature.** Written only for a registrar whose `plan.get` lists it. The git
  section names `worktree_tree`, `index_tree` and `raw_tree` in their own fields, and `refs` holds
  the repository's refs whatever their names (a user ref under `refs/sealant/capture/` was
  dropped by every restore). `raw_tree` holds each file's bytes as they are on disk, and a
  restore writes them back without smudge, end-of-line or encoding conversion: CRLF under
  `text eol=lf`, clean filters, `working-tree-encoding`, `eol=crlf` and `ident` come back byte
  for byte. The user's index and attributes are untouched. A reader of a manifest without the
  fields takes only the two exact pseudo-ref names as trees. `plan.get`'s `manifest_features`
  now lists `git_trees`.
- **Git state fidelity.** A symbolic `HEAD` is its immediate target (`HEAD -> alias -> main`
  restored as `HEAD -> main`). Every object `FETCH_HEAD`, `ORIG_HEAD`, `MERGE_HEAD`,
  `CHERRY_PICK_HEAD`, `REVERT_HEAD`, `REBASE_HEAD`, `AUTO_MERGE`, the `BISECT_*` files and a
  rebase's, `am`'s or sequencer's state name is packed (a fetch with no destination ref lost its
  commit). A nested repository whose name is not UTF-8 is carried whole (it was dropped). A path
  the worktree tree leaves to the workspace class that holds something on disk and no class
  carries fails a final snap instead of being acknowledged as saved.
- **Remotes are the user's.** Plan remotes are added only where the repository has none of that
  name and never change an existing URL. A resumed or recovered disk keeps its remotes (recovery
  replaced a user's changed `origin` before saving it).
- **Recovery binds to the capture it materialized.** A recovery boot without staging that
  continues the head resumes the disk only when its recorded materialize (capture id, executor,
  epoch) is exactly the plan's head and not from a later epoch. It used to compare the worktree
  tree alone. A disk materialized by an older daemon has no record and is refused.
- **`sealantd boot --recovery`, and one daemon per disk.** `--recovery` is `SEALANT_RECOVERY=1`
  as a flag, for a still-running MicroVM whose daemon exited (Core's agent spawns it with the same
  boot environment). Every capture boot holds an exclusive lock on `<worktree>/.sealantd/boot.lock`
  for its lifetime; a second boot on the same disk exits 75 and touches nothing. Recovery exits 0
  only when its final flush is complete, else 75.
