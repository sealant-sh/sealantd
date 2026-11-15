# Changesets

Adding a change to a release: run `pnpm changeset`, pick the bump (patch/minor/major), and describe
it. Commit the generated `.changeset/*.md` file in your PR.

On merge to `main`, the `version` workflow opens a **Version Packages** PR that bumps both SDK
packages (they are `fixed` together) and updates CHANGELOGs. Merging that PR + pushing a `vX.Y.Z`
tag triggers the gated release (`release.yml`).

The Version Packages PR gets its required checks (`rust` and `node`) without a hand step. The
workflow pushes its branch as `github-actions[bot]`, so GitHub holds the `ci` run that push creates
at `action_required`, with no jobs. The workflow's `approve-checks` job, which holds only
`actions: write`, then approves that held run on the branch's new head, so it runs as an ordinary
pull request run and reports on the commit the PR merges. Every merge to `main` rebuilds the branch
and the job approves the new run. If the job fails, approve the held run on the PR's Checks tab
("Approve and run workflows").
