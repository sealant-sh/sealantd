---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Dotfiles detection, `HOME` and the arm64 loader shim (daemon-only; the packages ride the release
train).

`manager: auto` picked stow for any tree with a non-dot top-level directory, and stow skips
top-level dot entries. A home mirror (`.config/`, `.zshenv`, `.gitconfig` beside `bin/`,
`Library/`) therefore had none of its dotfiles applied and its plain directories stowed into
`/root` instead. Auto now picks stow only for a stow layout: package directories and no top-level
dot entries except repository and stow metadata (`.git`, `.gitignore`, `.github`, `.stowrc`, …).
Plain top-level files such as `README.md` or `Brewfile` still allow stow. A mixed tree is copied.
Only the top level is examined, so a `*.tmpl` deep inside a home mirror does not select chezmoi.
A chezmoi source whose `chezmoi` binary is missing is copied rather than stowed. Boot logs the
resolved manager and what decided it.

An explicit `manager: stow` copies the top-level dot entries into the target before stowing the
packages and logs their names. Before this it dropped them without a log line. The copy manager
now recreates symlinks as symlinks, as `cp -a` does, so a dangling link no longer fails boot. It
also replaces an existing file or link at the destination instead of writing through it.

`chezmoi apply` (now with an explicit `--destination` and `--no-tty`), `stow`, the dotfiles clone
and the `./install.sh` bootstrap run with `HOME`, `USER` and `LOGNAME` set to the workspace home
and without the `XDG_*_HOME` overrides. They no longer depend on the environment the runtime
started PID 1 with. A MicroVM's init supplies no `HOME`.

On a Nix base the glibc loader shim links the running architecture's loader,
`/lib/ld-linux-aarch64.so.1` on arm64 as well as `/lib64/ld-linux-x86-64.so.2` on x86-64. It
used to look only for the x86-64 one.
