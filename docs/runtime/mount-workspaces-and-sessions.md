# Mount-based workspaces and durable interactive sessions

Daemon-side contract for the two capabilities added for the agent-workbench direction
(Mend plan §8.1.A/§8.1.B), plus the file-watch default flip. This is the coordination surface for
the Core control plane; everything here is drivable today with zero Core changes via
`blueprint.runtime.env` (emitted last-wins after the repo vars) plus one `docker run -v`.

## 1. Mount-based workspace provisioning

A workspace's repository directory can come from a **caller-owned host path** (e.g. a git worktree
in a product-managed store) bind-mounted over the working directory, instead of a boot-time clone.

Env contract (all consumed by `sealantd boot`):

| Variable | Meaning |
| --- | --- |
| `SEALANT_WORKSPACE_SOURCE` | `clone` (default, existing behavior) or `mount`. |
| `SEALANT_WORKSPACE_MOUNT_HOST_PATH` | Host path backing the mount (provenance + allowlist check). Required in mount mode; rejected in clone mode. |
| `SEALANT_MOUNT_ALLOWED_STORE_ROOTS` | Colon-separated absolute store roots, **operator-configured** (must come from machine/operator config, never from the create request). The host path must be a proper descendant of one root. Required in mount mode. |

Mount-mode invariants, enforced at boot:

- The clone (and clone-auth materialization) is skipped entirely; the mount IS the repo.
  `SEALANT_WORKSPACE_REPO_URL` must not be set.
- Boot fails fast unless the working directory is an actual mountpoint (checked against
  `/proc/self/mountinfo`, so same-filesystem bind mounts are detected) and writable — a mount-mode
  boot on a plain container directory would silently strand writes in the container layer.
- The daemon never cleans, reprovisions, resets, or deletes the mounted contents under any
  lifecycle event. The clone path's dirty-directory `rm -rf` refuses to touch any mountpoint even
  in a misconfigured clone-mode boot. Teardown is `docker rm -f` of the container; the bind-mounted
  host contents survive by construction.
- The workspace root (`.ssh-runtime` state) must live outside the mount; boot rejects a layout
  where it does not.
- Recording, exec, redaction, PTY, and network semantics are identical to clone-based workspaces.

Orchestrator obligations (Core adapter, when it grows a mounts knob): canonicalize the host path
before launch (the daemon's allowlist check is lexical — it cannot resolve host symlinks from
inside the container), establish the bind mount before the container starts (docker `-v` does),
and keep `stop == docker rm -f` (never `rm -v`; there are no volumes to remove).

Suggested SDK shape (per Mend feedback): `workspaces.create({ source: { kind: "mount", path } })`
lowering to the env vars above plus the `-v <path>:/workspace/repo` mount.

## 2. Durable interactive PTY sessions

Sessions were already PTY-backed and disconnect-surviving; they now have a durable, redacted,
replayable output journal and full lifecycle reporting.

- **Journal**: every output chunk is redacted, appended to a per-session on-disk journal
  (CRC-checked records, contiguous sequences from 0, two rotating segments bounded by
  `session_journal_segment_bytes`, default 16 MiB each), and only then fanned out. Output produced
  while no client is attached is retained. Journals live under `SEALANT_SESSION_JOURNAL_DIR`
  (default `/var/lib/sealantd/session-journals`).
- **Reattach + scrollback**: `attachSession` takes optional `fromSequence`. The journal is
  replayed first (data-frame `seq` = journal sequence), then live output continues gap-free on the
  same channel. Attaching to an exited session replays the retained scrollback and then delivers
  the final `End{exitCode, signal}` frame.
- **Poll reads**: `readSessionOutput{sessionId, fromSequence, maxBytes?}` returns a batch of
  journal records plus cursors (`nextSequence`, `firstAvailableSequence`) and lifecycle state —
  the same resumable-cursor shape as `run.record.stream({ from })`.
- **Signals**: `signalSession{sessionId, signal}` delivers SIGINT/SIGTERM/… to the session's
  process group. `closeSession` remains SIGHUP for running sessions.
- **Lifecycle**: `SessionSummary` now carries `state (running|exited)`, `exitCode`, `signal`,
  `startedAtMicros`, and the journal cursor bounds. Exited sessions persist as tombstones (up to
  128, FIFO-evicted) so a re-fetched handle can observe the exit and replay the scrollback;
  `closeSession` on a tombstone drops it and its journal files.
- **Client**: `@sealant/runtime-client` gained typed `openSession` / `closeSession` / `resizePty` /
  `listSessions` / `signalSession` / `readSessionOutput` and `attachSession(id, { fromSequence })`.
  The client also buffers channel frames that arrive ahead of the response carrying their channel
  id (journal replay does this by design).

TTL note: the daemon has no TTL — expiry is entirely control-plane. Because a mounted workspace's
work product lives on the host path, an expiring TTL that `docker rm -f`s the container can never
violate the mount invariant. For PTY-attached workspaces Core should either exempt workspaces with
running sessions from the default TTL or refresh `expiresAt` while `listSessions` reports a
running session — the daemon exposes the signal, the policy is Core's.

## 3. File events (watch on by default)

`SEALANT_WATCH_FILESYSTEM` now defaults **on** (opt out with `0`/`false`). Watch registration is
pruned per-directory by the ignore list (`.git`, `node_modules`, `target`, …), new directories are
adopted live, and file events are stamped with the active execution id (the last started
exec/openSession/executionStart wins), so a run's edits correlate to that run. `capabilities` and
`health.featureStates` both report the real watcher state, and a watch-start failure is loud.

## 4. Demos

`packages/runtime-client/demo/demo-mount.sh` and `demo-pty.sh` run the definition-of-done
end-to-end against a real container (bind-mounted store worktree, `docker exec socat` control
bridge — the same transport Core uses): allowlist rejection, mount boot without clone, exec and
PTY edits producing `fileChange` events, kill-client → reattach → full scrollback replay from
sequence 0, input/resize taking effect, SIGTERM → exited tombstone → post-exit replay, and host
persistence after `docker rm -f`.
