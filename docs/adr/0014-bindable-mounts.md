# ADR-0014: Bindable mounts — the daemon binds a mounted root's subdirectory on demand

Status: accepted 2026-09-02. Cross-repo context: Mend `docs/adr/0001-standby-workspaces-bind-at-claim.md`
(the product decision), Sealant Core (standby source, bindable extra mounts, `workspace.bind`).

## Context

A running container's mount set is fixed on both Docker and Kubernetes. Mend keeps a pool of ready
workspaces so a session attaches instantly, and until now a pooled workspace had to be bound to one
git worktree at creation: joining an existing worktree, resuming, and rejoining could never be
served from the pool, and every pooled workspace spent a worktree ahead of time. The platform needs
a way to decide *which* directory a workspace works in after the container exists.

## Decision

The orchestrator mounts the **root** (a project's worktrees directory) at a hidden path, and the
daemon owns the path the workspace actually uses. A new `bindMount { mountPath, subpath }` command
points `mountPath` at `<root>/<subpath>` as a symlink; an empty subpath unbinds. Boot reads
`SEALANT_BINDABLE_MOUNTS` (the roots) and `SEALANT_BINDS` (what to bind before the harness starts),
and `SEALANT_WORKSPACE_SOURCE=standby` makes the working directory itself bindable, rooted at
`<workspace root>/.roots/workspace`. Every bind is recorded under `/run/sealant/binds.json` and
re-applied when the daemon restarts inside the same container; across container recreation the
orchestrator re-supplies `SEALANT_BINDS`.

The daemon validates what it can: the mount path must be declared bindable, the subpath must be
relative with no `.` or `..`, the target must exist as a directory under the root, and the mount
path is never bound over a real file or a non-empty directory. Because git sees the symlink's real
path, a bind adds that path to the system `safe.directory` list when it holds a repository.

## Considered options

- **Pre-created empty directories per pooled workspace.** kubelet creates a missing subPath and git
  populates an empty directory, so the orchestrator could pre-mount not-yet-existing worktrees.
  Cheaper, but it still cannot serve an existing worktree.
- **A real bind mount inside the container.** `mount --bind` needs `CAP_SYS_ADMIN`, which the
  workspace deliberately does not have. A symlink gives the same result for every tool that
  matters (git, editors, the harness) without the privilege.

## Consequences

- A standby container sees every subdirectory of its root. The root is a project's worktrees
  directory, never the whole store, so exposure stays within one repository's sessions.
- `/workspace/repo` is a symlink in standby workspaces. Tools that resolve real paths see
  `/workspace/.roots/workspace/<worktree>`; the safe-directory entry covers git.
- Boot fails when a promised bind cannot be applied. A harness must never start against a working
  directory the platform said would exist.
