---
"@sealant/runtime-protocol": patch
---

A `host-vm` workspace that was hard-killed seconds after an edit, a `git commit` or a capture now recovers its saved work. A kill before Linux wrote the newest git objects back to disk leaves them as empty files, even though the edited files themselves were synced. The recovery boot's final flush then failed in `git pack-objects` (`object file … is empty`): `FINAL CAPTURE INCOMPLETE reason=snapshot-failed`, exit 75, and the edit was never recovered. The capture now removes empty loose objects before it packs a repository, and again whenever a pack fails. A file whose blob was lost is read from disk again. A ref or reflog entry that names a commit the crash lost is left out of the pack and restored as the disk holds it. The final flush completes and restores every file of the worktree byte for byte. Every git the capture runs now flushes its writes to disk before it returns (`core.fsync`, with `core.fsyncMethod=batch`), so a capture no longer leaves empty objects behind it. The log says `removed an empty loose object, which a crash left before its bytes reached the disk`.

`sealantd --vm` now names the guest `workspace` at boot and makes `/etc/hosts` resolve it, so `sudo` in a `host-vm` workspace no longer prints `sudo: unable to resolve host (none)`. An `/etc/hosts` the image or the user wrote keeps every line and gains `127.0.1.1 workspace` only when no line names the host already.

Before powering off, `sealantd --vm` now remounts the data disk read-only after syncing it, so `e2fsck -fn data.img` finds the filesystem clean with no journal to replay. A disk still in use (`EBUSY`) is logged as `still in use, left read-write for the power-off`, and the power-off goes ahead.
