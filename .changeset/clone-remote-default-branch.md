---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Boot clone honors the repository's default branch when no ref is given. `SEALANT_WORKSPACE_REPO_REF` is now optional (missing or empty means "the remote's default branch"): the boot clone only passes `--branch` when a ref was explicitly provided, so a plain `git clone` resolves the remote HEAD. Previously the env var was required and the control plane injected `main`, which broke every repository whose default branch isn't `main` (e.g. `master`) with `fatal: Remote branch main not found in upstream origin`.
