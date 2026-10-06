---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Processes as a person's user (Mend's per-person layout). `exec` and `openSession` take `user`, a
login name or a decimal uid: the process starts as exactly that passwd entry (uid, primary and
supplementary groups, `HOME`, `USER`, `LOGNAME`, `SHELL`, umask `0002`, a private `TMPDIR` and
`XDG_RUNTIME_DIR`), and every child inherits it; a PTY leader owns its terminal.

The dotfiles applier runs as a user into their home: at boot with `SEALANT_DOTFILES_USER`, and
through the new `dotfiles.apply` command, which answers once the files are applied and runs
`./install.sh` after them as a managed process of that user.

`supports` names `exec.user` and `dotfiles.user` beside `restore.owner_map`, and
`sealantd capabilities --json` prints them without booting.
