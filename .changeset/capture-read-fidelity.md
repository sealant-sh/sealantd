---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

A capture holds what is on disk, and a final one fails when it cannot (daemon-only; the packages
ride the release train).

A user's `*.lock`, `*.pid`, SQLite `-shm` and `.pack` files are captured; only git's own
transient files inside a git directory are left out. Local git-lfs objects (`.git/lfs/`) are
captured. A file or directory that exists but cannot be read is no longer captured as deleted: a
`final` capture fails naming it, and any other capture carries its last read content, marked
`unread`. A same-size overwrite that puts the mtime back is seen (the change key includes the
ctime), a read right after a change is not trusted by the next capture, and a path the watcher saw
written is read again. File names and symlink text that are not UTF-8 keep their bytes: dir
entries gain optional `raw_name`, `raw_target` and `unread` fields, written only when they apply,
so every existing dir object is unchanged.
