---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

A restore brings back the working tree's metadata and exactly the captured refs
(daemon-only, plus one additive manifest field).

A git tree carries a file's bytes and its executable bit, nothing else, so a restored session
got every tracked file `0644`/`0755` with the time of the restore, lost its empty directories,
and got two files where it had one hardlinked file. A capture's workspace section now carries
`worktree_meta`: exact modes, nanosecond mtimes of files, symlinks and directories (the root
included), the directories git does not track, and hardlink groups, as a JSON document chunked
into the section's own packs (its `packs` are a subset of the section's, so retention and
presigning need no change). The materializer applies it after every class and fails, instead
of reporting a partial restore, when a path cannot be brought to it. A manifest without the field
restores as before, and a manifest with it encodes the field only when present. The shape is in
`crates/sealant-capture/README.md`, "`worktree_meta` in a manifest".

Names that are not UTF-8 are kept byte for byte in the document, written as the same escaped keys
dir objects use for names with the bytes in hex beside them. A tracked file hardlinked to an
ignored file or to a file under a bulk directory comes back as one inode when every name holds
the same bytes, and as separate byte-exact files when the bulk capture is older.

A rematerialize removed only the loose refs the manifest named, so a branch, a remote-tracking
ref or a stash the disk held beyond the manifest survived it. Every loose ref is now removed and
`packed-refs` holds exactly the manifest's refs. Symbolic refs other than `HEAD`
(`refs/remotes/origin/HEAD`) came back as plain refs; the git section now carries them in an
additive `symrefs` map (name → target, absent when empty) and a restore writes them symbolic.

Chunked-class symlinks get their own mtime back, and a directory mode or mtime, a hardlink or a
hardlink canonical outside the class roots that cannot be restored fails the materialize instead
of being skipped. A bulk section older than the worktree tree no longer sweeps or overwrites a
tracked file under a bulk-named directory such as `build/` or `dist/`.

A tracked path whose metadata cannot be read (under a directory that cannot be searched) keeps
its previous entry in an automatic capture and is counted in `capture.status`'s `unreadable`; a
final capture fails on it, as it does on any work it cannot read.
