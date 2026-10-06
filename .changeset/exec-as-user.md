---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Processes as a person's user (Mend's per-person layout). `exec` and `openSession` take `user`, a
login name or a decimal uid: the process starts as exactly that passwd entry (uid, primary and
supplementary groups, `HOME`, `USER`, `LOGNAME`, `SHELL`, umask `0002`, a private `TMPDIR` and
`XDG_RUNTIME_DIR`), and every child inherits it; a PTY leader owns its terminal. Where the daemon
has no no-new-privileges (so `sudo` works), the process also holds `CAP_FOWNER`, ambient, which
amounts to root; `runtime.getCapabilities` reports `personCapabilities` and, when withheld, why.
Such a process inherits no harness or provider login, no declared harness key and no `SEALANT_*`
key from the daemon's environment; the project's secrets reach it. The dotfiles commands run with
a clean, explicit environment. The image's `/etc/sealant/person-env` (first line
`# person-env 1`, then literal `KEY=VALUE` lines, `PATH_PREPEND` in front of `PATH`) applies to
every process run as a person, never to root, under the caller's explicit variables.

The dotfiles applier runs as a user into their home through the new `dotfiles.apply` command,
which answers once the files are applied and runs `./install.sh` after them as a managed process
of that user. It is used once the user exists, the launcher included; boot still applies root's
dotfiles into `/root`, and no user needs to exist at boot.

`supports` names `exec.user` and `dotfiles.user` beside `restore.owner_map`, and
`sealantd capabilities --json` prints them without booting.
