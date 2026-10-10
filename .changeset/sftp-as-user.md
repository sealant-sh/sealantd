---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

An SFTP bridge runs as a person's user. `openSftp` takes `user`, a login name or a decimal uid,
admitted exactly as for `exec` (one of the executor's people, never root): the `sftp-server` starts
as that user with the environment an exec as them gets (the daemon's child environment less every
login and `SEALANT_*` key, the image's person environment, then `HOME`, `USER`, `LOGNAME`,
`SHELL`, `TMPDIR` and `XDG_RUNTIME_DIR` from their passwd entry), so what it reads and writes is
theirs to read and write, and what it makes is theirs. Without `user` nothing changes: root, with
the daemon's environment. `supports` names `sftp.user`, which an SSH gateway reads before it sends
a user, since an older daemon ignores the field and would run the bridge as root.
