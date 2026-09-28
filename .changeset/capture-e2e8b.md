---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The eighth end-to-end run's remaining daemon findings (F7, F4b; F3 documented as unsupported).

- **A standby no session claimed has nothing to save (F7).** A standby's boot (its launch is
  `standby:<id>` and its launcher named no worktree) writes `.sealantd/capture/unclaimed.json` on
  the disk's first boot, once its base is materialized. The first `capture.replan` that acts on
  its plan, or the first control command that admits a writer (`exec`, `writeStdin`,
  `openSession`, `attachSession`, `openForward`, `openSftp`, `bindMount`, `execution.start`),
  removes it durably before it acts. A final flush that still finds it answers at once, with no
  snap, no ship and no wait: `complete: true`, `pending: 0`, no `incomplete_reason`, under the
  placeholder's `worktree_id`, `epoch` and `launch`. It drops the placeholder's queue, the daemon
  ends by itself with exit **76** (`EXIT_NOTHING_TO_SAVE`), and nothing is admitted after that. A
  recovery boot on that disk exits 76 before `plan.get`, with `sealantd boot: nothing to save: a
  standby no session claimed (…)` on stderr, which Core's recovery sweep already releases on
  (`nothing-to-save`). Once any claim or writer was admitted none of this applies again.

  Before, a claimed standby whose re-plan failed kept its placeholder captures queued forever
  (`lease-lost`). Its final flush never completed, and the launch waited 12 minutes, failed and
  needed a discard. Mend binds a `complete` answer to the lease epoch its claim took, so to act
  on the answer itself it must read a claimed standby's answer under the placeholder's epoch and
  its `standby:<id>` launch as nothing to save. Until then it sees the executor end.
- **A base restores in its own formats (F4b).** When the plan's workspace class carries no
  `.git/config` or reftable tables (Mend's capture 0), the workspace sweep now leaves the ones
  `git init` wrote. After every class, the restore writes `core.repositoryformatversion`,
  `extensions.objectformat` and `extensions.refstorage` back if the repository no longer reads in
  the git section's formats. It does this before the boot adds remotes or seeds the engine.
  Before, a SHA-256 base restored as a SHA-1 repository and `git for-each-ref` failed on its
  64-hex `packed-refs`, and a reftable base lost every ref.
- **Not supported (F3):** a repository that changes object format mid-session. Its next git
  section still lists the previous format's packs, and the registrar refuses the seal. Mend
  refuses SHA-256 and reftable projects at adoption.
