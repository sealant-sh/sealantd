---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Processes as a person's user (Mend's per-person layout). `exec` and `openSession` take `user`, a
login name or a decimal uid: the process starts as exactly that passwd entry (uid, primary and
supplementary groups, `HOME`, `USER`, `LOGNAME`, `SHELL`, umask `0002`, a private `TMPDIR` and
`XDG_RUNTIME_DIR`), and one capability, `CAP_FOWNER` (ambient), and every child inherits it; a
PTY leader owns its terminal. Such a process
inherits no provider token, no `SEALANT_*` key and nothing secret-looking from the daemon's
environment, and the dotfiles commands run with a clean, explicit environment. The image's
`/etc/sealant/person-env` (literal `KEY=VALUE` lines, `PATH_PREPEND` in front of `PATH`) applies to
every process run as a person, never to root, under the caller's explicit variables.

The dotfiles applier runs as a user into their home through the new `dotfiles.apply` command,
which answers once the files are applied and runs `./install.sh` after them as a managed process
of that user. It is used once the user exists, the launcher included; boot still applies root's
dotfiles into `/root`, and no user needs to exist at boot.

`supports` names `exec.user` and `dotfiles.user` beside `restore.owner_map`, and
`sealantd capabilities --json` prints them without booting.
