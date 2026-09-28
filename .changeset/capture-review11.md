---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The eleventh adversarial review's daemon findings (#1, #2) and the carried tenth-review #6;
cross-repo decisions 29, 33 and 35.

- **Bare repositories and symlinked object stores are part of the closure (#1, decision 29).**
  A git directory with no worktree — a bare repository in the worktree tree, an ignored or bulk
  directory, or `.git/modules/` — is found by its `HEAD` (as git decides a git directory) and
  classified like a nested repository. Every nested repository's primary object store is
  resolved through symlinks before its alternates are followed, and relative alternates are
  taken from the store's real path. One that borrows the top-level store, through alternates or
  an `objects` symlink, gets the objects its own state reaches there packed beside the closure;
  one whose storage is outside the workspace, or one that borrows it where git cannot be asked
  what its state reaches, makes a final flush `snapshot-failed`, naming it. Before, a bare `child.git` borrowing the top-level store
  and a nested `.git/objects -> ../../.git/objects` both sealed without the objects only they
  reached.
- **Only git's own transaction files are transient (#2, decision 33).** The name filter inside a
  git directory is an allow-list of git's lockfiles and temporary objects, each where git writes
  it (`index.lock`, root refs' locks, `config.lock`, `packed-refs.lock`, `refs/**.lock`,
  `logs/**.lock`, the object store's locks and `tmp_*`/`incoming-*`, the same in
  `worktrees/<name>/` and `modules/<name>/`). Any other file is captured in every class: a hook
  project's `.git/hooks/Cargo.lock` and a config include called `.git/personal.lock` were
  dropped, and a sealed restore lost them. A `.pack` is judged by its `.idx` only in
  `objects/pack/`. A transaction lock found by a final flush is stale (every writer was stopped)
  and is dropped, never restored and never a reason to refuse the flush.
- **A final flush names itself on the wire (carried review 10 #6, decision 35).** From the moment
  a final flush begins — a drain, a runtime deadline, `SIGTERM`, a recovery boot — every
  `upload.urls` and `capture.register` the executor sends carries `"flush":"final"` until it
  exits, so the registrar can exempt preservation from its byte and call quotas. Additive: an
  older registrar ignores the member and meters the request as before.
