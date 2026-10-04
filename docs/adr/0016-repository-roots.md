# Repository roots: one capture engine per repository a session holds

Status: proposed 2026-10-03. Cross-repo: Mend ADR 0010 (repositories in a session: the product
decision, the interim that ships without this change, and the Mend half of the capture channel).
Amends ADR-0015 ("Capture format", "Ports and crate layout", "Lifecycle"). Nothing here is built
yet; this records the design the daemon is asked to implement.

## Context

A Mend session works in one worktree, materialised at `/workspace/repo`, the daemon's working
directory and its only capture root (`CaptureConfig.root`, `boot/config.rs`
`DEFAULT_WORKING_DIRECTORY`). Mend now lets a session add any other project of its store as a
**repository**: a worktree of that project at `/workspace/repos/<name>`, on a branch of its own for
the session, with its own change, checkpoints and landing on Mend's side (Mend ADR 0010).

Today nothing outside the root is listed, watched or restored. The manifest holds one git section
and one workspace root (`manifest.rs` `Sections`), the git class packs the repository at the root,
and a nested repository under the root travels as plain files in the workspace class, kept out of
the root's tree by `:(exclude)` pathspecs (`gitpack.rs` `nested_repositories`,
`tests/nested_repos.rs`). Mend's shipped interim uses exactly that: it clones the sibling at
`/workspace/repo/.mend/repos/<name>` and links `/workspace/repos/<name>` to it, so the sibling is
saved and restored with the main worktree, and nothing of its own reaches Mend's store as git
packs. The consequence on Mend's side: the sibling's chain stays at capture 0, so Mend cannot diff,
checkpoint or land it from the store.

`sources` (`boot/sources.rs`) do not serve this: a source is a read-only archive under
`/workspace`, capped at 64 MiB, re-extracted at every replan, with nothing travelling back.

## Decision

### A repository is a root of its own, under its own worktree identity

The daemon runs **one capture engine per repository root**, beside the one for `/workspace/repo`.
Each engine has its own `CaptureConfig` (`root = /workspace/repos/<name>`, its own staging dir
under that root, the same `bulk_dirs`), its own `worktree_id` and `epoch`, and registers its own
captures through the same registrar routes under its own identity. The harness home belongs to the
main engine only; a repository engine captures no `harness/` child. The lease is per worktree on
Mend's side (Mend ADR 0002 "The key is the worktree"), so the executor holds one lease per
repository and heartbeats each.

Nothing in the manifest format changes for a single root: a repository's manifests are ordinary
manifests of its own worktree id. What changes is that one executor registers under several
worktree ids, which Mend's channel admits for the session's repositories (today it answers 409
`wrong-worktree` to any id but the main one).

### `plan.get` names the repositories

`PlanGetResponse` gains `repositories: Vec<PlanRepository>`:

```rust
pub struct PlanRepository {
    /// The directory name under /workspace/repos/.
    pub name: String,
    /// Absolute path of the root: /workspace/repos/<name>.
    pub path: String,
    pub worktree_id: String,
    pub epoch: u64,
    /// The chain head to materialise from; None at capture 0 with nothing registered yet.
    pub head: Option<HeadInfo>,
    pub get_urls: BTreeMap<String, String>,
    /// How this executor was told to treat a directory already at `path` (see "Adopt").
    pub existing: ExistingRoot, // `materialise` | `adopt`
}
```

The main worktree's fields stay where they are. An older daemon ignores the field and captures
`/workspace/repo` alone, which is the interim Mend ships today; so the field is advertised through
`manifest_features` as `repositories`, and a daemon that reports the feature is one Mend may ask
to carry roots. Mend's `plan.get` lists repositories only to a daemon that reports it.

### Boot, pickup and replan

- **Boot and pickup.** After the main root is materialised, each listed repository is materialised
  from its own head into its path, exactly as the main worktree is: git class into a repository
  with `.git/index` protected, workspace class into `tree/`, bulk by platform. Then its engine
  starts, its lease is claimed by the same executor (Mend claims every repository's lease at the
  same launch and answers each `plan.get` under its own worktree id), and watching begins.
- **Replan.** `capture.replan` re-reads the plan. A repository in the answer that has no engine yet
  is brought in without restarting anything else: materialised when its path is empty, **adopted**
  when the path already holds a repository (below). A repository that disappears from the answer
  is left on disk and its engine stopped; Mend never asks that today.
- **Adopt.** `mend repo add` while the session runs clones the sibling inside the workspace (Mend
  does this through the workspace's own git transport) and then asks for a replan. The daemon finds
  a repository at `path` with no engine: it takes an immediate `checkpoint` snapshot of what is
  there and registers it as the chain's first capture under this executor's epoch, so Mend's store
  holds the sibling from the moment it exists. The same path serves the one-time move from Mend's
  interim: Mend moves `/workspace/repo/.mend/repos/<name>` to `/workspace/repos/<name>` and asks
  for a replan. A path that holds something that is not a git repository fails the adopt with
  `not_a_repository` and the main engine is unaffected.

### Snaps, flushes and the final flush

Each engine snaps on its own cadence and ships through the shared uploader; the byte quota stays
per session on Mend's side. A `flush` (suspend or final) runs every engine's flush and answers
`complete` only when every one is complete; `pending` counts and `pending_bytes` are summed across
engines and also reported per root, so Mend's `stopping · saving · N left` can name the root that
is behind. A final flush quiesces processes once, then snaps every root. Fenced or refused answers
are per engine: a repository whose lease was lost pauses nothing in the main root, and the status
names which root is fenced.

### What stays the same

- The main root's `nested_repositories` exclusion stays: a repository under `/workspace/repos/` is
  not under the main root, so the main engine never sees it. A sibling that is still nested inside
  the main root (the interim) is carried as it is today until Mend moves it.
- The workspace class carries no `harness/` for a repository root; `HARNESS_CREDENTIALS` therefore
  never applies there.
- `sources` and binds (ADR-0014) are untouched. A repository is neither.
- The capture format is unchanged per manifest; only `manifest_features` grows.

## Consequences

- Mend's review, checkpoints and landing work for a sibling exactly as for the main worktree, from
  verified git packs in the store, the day this lands: the sibling is a worktree with a chain.
- One executor heartbeats N leases and ships N chains; a byte quota that is per session must be
  shared across them on Mend's side, which it already is (per `upload.urls` call and per session).
- A pickup materialises N roots before the harness starts; cold start grows by the siblings' size.
  Mend already keeps the dependency cache per project, so a sibling's `node_modules` comes from
  its own project's cache.
- An old daemon on a new Mend keeps the interim: nothing breaks, Mend reads the missing feature and
  keeps nesting.
- The move from nested to own happens once per session and only when a capable daemon boots it;
  Mend drives it and records which it is (`capture: nested | own` on its row).

## Alternatives considered

- **One manifest with several git sections.** Changes the fixed format for every reader, couples
  N roots' failure modes into one register, and gives Mend a capture that is not a worktree's.
  Rejected: a repository is a worktree, so it gets a chain.
- **Make `/workspace` the root.** `/workspace/repo` becomes a nested repository carried as files,
  every `sources` path is refused (they must sit outside the worktree), and the harness home moves
  under the root. Rejected.
- **Carry the sibling as a nested repository for good** (the interim). Saved and restored, but
  Mend holds it as chunked files, not git packs: no diff, checkpoint or landing from the store, and
  every sibling commit re-chunks `.git/objects`. Kept only until this lands.
- **A `sources` entry per sibling.** Read-only, capped, nothing travels back. Not a worktree.

## Open questions

1. Whether a repository engine shares the main engine's inotify budget or has one of its own; a
   sibling the size of a monorepo could push the main root to polling.
2. Whether `repositories` removed from the plan should stop the engine only, or also remove the
   directory. Mend has no in-session remove verb yet, so nothing asks today.
3. Whether the adopt snapshot should be `checkpoint` or a new `adopt` kind, so Mend can tell a
   chain that began from an executor's disk from one that began from the store.
