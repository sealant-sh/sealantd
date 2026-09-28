---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The ninth adversarial review's daemon findings (#1, #2, #3 and the executor side of #7), and
cross-repo decision 24.

- **Git state is read through git (#1, decision 24).** `HEAD`, the refs, the reflogs and the
  root refs are read with backend-aware git (`symbolic-ref --no-recurse`, `rev-parse`,
  `rev-list --reflog --stdin`, `for-each-ref --include-root-refs`), never from `.git/HEAD` or a
  `logs/` directory. In a reftable repository the `HEAD` file is `ref: refs/heads/.invalid` and
  there is no `logs/`: a commit only its reflog, its detached `HEAD` or its `ORIG_HEAD` reached
  was left out of a sealed capture, and a cold restore lost its file. The git section names the
  backend (`ref_format: "reftable"`, a new manifest feature, absent for `files`); the restore
  initializes the repository with it and writes the refs through git. A store that does not read
  `ref_format` gets no complete final flush of a reftable repository.
- **A ref symlink comes back as a symlink (#2).** `.git/refs/heads/alias -> main` (git reads the
  file it reaches) was dropped from the workspace class because its text is not a ref name.
  Every symlink under `.git/refs/` and at `.git/HEAD` is carried now, and the restore writes the
  ref file its chain ends on loose again so it resolves. One that reaches outside the repository
  makes a final flush `snapshot-failed`.
- **Times past 2262 (#3).** A modification time outside signed 64-bit nanoseconds saturated and
  sealed. A final flush over one (any class, directories too) is `unreadable`, naming the path.
- **Hardlink groups with different bytes (#7).** A strict restore refuses to relink a tracked
  hardlink group whose names hold different bytes; a lenient one leaves them apart.
