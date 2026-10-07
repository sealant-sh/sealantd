---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

A person's `dotfiles.apply` hardened further (review of #149):

- **Sizes:** an archive is refused before anything is extracted when its listing unpacks to more
  than `SEALANT_DOTFILES_MAX_UNPACKED_BYTES` (default 256 MiB) in all, or more than
  `SEALANT_DOTFILES_MAX_FILE_BYTES` (default 64 MiB) in one file.
- **Links:** an archive is refused when a link sits at its root (`.`), or when a hard link's
  target is absolute, has a `..`, lies under one of the archive's links, or is not an entry of
  the archive. These no longer rely on GNU tar's own protections.
- **One read:** the archive is read once, through a descriptor that does not follow a link, into
  root's staging, and every listing and the extraction read that copy.
- **No process from the writer thread:** the process gate refuses a spawn from a thread acting
  with a person's filesystem identity, whose child would run as root.
- **Dumpable:** the daemon is dumpable again after an apply, as it was before it.
- **Staging sweep:** only this pid's leftovers from an earlier daemon are removed; another
  daemon's are left alone.
- **Tree mode:** the person's tree under `~/.local/share/sealant-dotfiles/<i>` takes the mode it
  had before #149 (the daemon's umask) instead of 0700.
