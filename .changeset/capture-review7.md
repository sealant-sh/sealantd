---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The seventh adversarial review's daemon findings (#1, #2, #10) and the executor side of
cross-repo decision 20.

- **A symbolic ref stored as a symlink stays one (#1).** With `core.preferSymlinkRefs=true` git
  stores a symbolic ref (`HEAD` included) as a symlink whose link text is the target's name. The
  capture read regular files only: a sealed restore brought `refs/heads/alias -> refs/heads/main`
  back as a direct ref, and a dangling one not at all. `symrefs` now holds every symlink git reads
  as a symbolic ref, by its link text (dangling, chained, names that are not UTF-8), and a
  symlinked `HEAD` is its link text. How it was stored is kept too: the workspace class carries
  the symlink itself (link text and mtime), which the restore puts back after the git class wrote
  the ref as text. A restore over a symlinked `HEAD` replaces the link instead of writing through
  it into the branch it names.
- **The `.git` and harness roots keep their mode and mtime (#2).** The restore wrote what is
  under them and left both `0777` under the umask with the time of the restore. Both are now set
  from the workspace class's root entries last of all.
- **One inode, one mode, one mtime (#10).** A strict restore of a sealed capture refuses, before
  it changes anything, a worktree metadata document that promises names of one inode (a hardlink
  group, a shared link, a cross-class group) different modes or mtimes
  (`MetaError::InodeConflict`). The writer never emits one: a final snap that reads an inode
  moving between two of its names fails (`snapshot-failed`, no seal); any other snap gives every
  name the first name's metadata and the next snap takes the change.
- **`present` is negotiated (decision 20).** Every `plan.get` request carries
  `"upload_answers":["present"]` (`registrar::UPLOAD_ANSWERS`). A registrar answers `present`
  only to an executor whose `plan.get` listed it, and a conditional URL (whose 412 every daemon
  takes as uploaded) to one that did not: an older daemon, like the binary on a retained disk,
  failed on `present` with `no url` on every retry.
