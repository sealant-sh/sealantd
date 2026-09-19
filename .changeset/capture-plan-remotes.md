---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Remotes for the repository of a capture-source workspace (daemon-only; the packages ride the
release train). `plan.get` may now answer `remotes`: per remote a `name` and a `url`. The boot
sets each one on the worktree's repository after it materializes the head, and `capture.replan`
sets those of the worktree it is assigned, because a standby executor boots under a placeholder.

The executor builds that repository itself: `git init`, then the head's packs. Remotes are
configuration of the control plane's own copy and never travel in a capture, so the repository a
harness worked in had none, and `git push origin` or `git fetch origin` failed with "'origin' does
not appear to be a git repository" in every captured session. Only the name and the URL travel;
how the remote is authenticated stays with the control plane. A missing remote is added, one that
points elsewhere is updated, and a remote the session added itself is left alone. A name or URL
that could read as an option fails the boot; a git failure is logged and skipped. A registrar that
answers no `remotes` is unchanged in every respect.
