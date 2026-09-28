---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The tenth adversarial review's daemon findings (#1, #2), the carried ninth-review #3, and the
format admission gap; cross-repo decision 29.

- **Every object a reflog names is packed (#1).** `git rev-list --reflog` lists commits only: a
  blob, a tree or an annotated tag a ref was moved away from was left out of a sealed capture in
  either ref backend, and the restored reflog named objects the repository did not hold. The
  other objects are now listed with `--objects`, the commits negated so no commit's tree is
  walked.
- **Nested repositories that share git storage (#2, decision 29).** A linked worktree inside the
  workspace keeps its `.git/worktrees/<name>` administrative directory (index, `HEAD`,
  `ORIG_HEAD`, reflog, per-worktree refs) in the workspace class, and its `HEAD`, refs, reflogs,
  every index stage and operation state join the top-level closure. A nested repository whose
  alternates (or common directory) are the top-level object store gets the objects its own state
  reaches there in a further pack of the git section. One whose git directory, common directory
  or alternates are outside the workspace makes a final flush `snapshot-failed`, naming it; so
  does one under a bulk directory that borrows the top-level store.
- **Times outside 1677–2262 are exact (review 9 #3, carried).** A modification time is recorded
  as nanoseconds since the epoch, exactly: a dir entry's and a worktree metadata entry's `mtime`
  is a JSON integer outside signed 64 bits for such a time (a wide time), written by automatic
  captures as by final ones, and restored exactly. Before, an automatic capture saturated it and
  a crash restore wrote the last nanosecond of 2262. A new manifest feature, `wide_times`: a
  store that does not read it gets no complete final flush over a wide time (`unreadable`); a
  registrar reports it held when a dir entry of the answered sections, or a worktree metadata
  entry, has an `mtime` outside signed 64 bits.
- **The repository is part of writer admission.** A SHA-256 repository needs the store to read
  `object_format` and a reftable one `ref_format`, whether the chain head names the format or the
  repository is on the disk: the boot exits 78 (`store-unfit`) and a standby's re-plan is
  refused before anything is materialized, instead of admitting writers whose final flush then
  says incomplete.
