---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

`dotfiles.apply` no longer writes into a person's home as root. Their archives are unpacked by root
into a directory of its own outside every home (`/run/sealant/dotfiles-staging`, 0700, removed once
the apply ends, failed or not), without owners, and an archive is refused before anything is
written when an entry has an absolute path, a `..`, lies under a link the archive makes, or is not
a file, a directory or a link. Every write into the home (directories, files, links, modes, the
trees under `~/.local/share/sealant-dotfiles`, the repository checkout's removal and the askpass
shim) is made as the person: on a thread whose filesystem uid, gid and groups are theirs and that
holds no capability. A link a person planted into another person's home now fails the apply,
naming the path, instead of letting root write through it. Root's own dotfiles at boot are applied
as before.
