---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Runtime dotfiles hardening + caller-provided archives: `sealantd boot` now applies dotfiles BEFORE
the control socket binds (readiness-gated injections like credential files can no longer race a
dotfiles apply into `$HOME`), `SEALANT_DOTFILES_REPO_REF` is optional (absent clones the remote's
default branch instead of assuming `main`), and a new `SEALANT_DOTFILES_ARCHIVE_DIR` input applies
caller-staged gzipped tars (`manifest.json` + `<n>.tar.gz`, per-archive manager/target/bootstrap)
through the same chezmoi/stow/copy dispatch — the transport for dotfiles resolved host-side with
the caller's own ssh identity or scanned from a home directory. Archive apply failures abort boot
like the repo path.
