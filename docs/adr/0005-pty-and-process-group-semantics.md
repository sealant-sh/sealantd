# ADR-0005: PTY and process-group semantics

## Status

Accepted, 2026-06-20

## Context

In today's flow, command execution is fully delegated: the image entrypoint starts an in-container `sshd` launched with `ForceCommand /usr/local/bin/workspace-ssh-shell`, and the ssh-gateway (`apps/ssh-gateway/src/gateway-server.ts`) opens an upstream SSH session and pipes channels (brief §1). The upstream `sshd` allocates the PTY and owns the shell/process lifecycle. sealantd replaces that foreground role: per the brief's insertion point (§1), the daemon is launched from `renderWorkspaceEntrypoint` (`buildkit-builder.ts` ~lines 819-840) before the sshd block, so the gateway's upstream shell/exec lands on a sealantd-spawned process rather than a bare login shell. The auth boundary does **not** move — `gateway-server.ts` `incomingConnection.on("authentication")` (line 151) keeps publickey-only auth, `ws-{id}` username parsing, and the allowlist check (brief §3). What moves to sealantd is the in-workspace PTY/process lifecycle: `pty/exec/shell/resize/signal` (brief §3).

The gateway call sites sealantd's session API must service are concrete (brief §3):

- `openSession` (shell) ← `session.on("shell")` → `upstream.shell(shellWindow, { env }, cb)` (`gateway-server.ts:259`), `shellWindow` carrying `{ cols, rows, width, height, modes }` from the stored `sessionPty` (lines 248-257).
- `openSession` (exec, optional PTY) ← `session.on("exec")` → `upstream.exec(info.command, { env, pty? }, cb)` (line 296); exit code returns via `upstreamChannel.on("exit", code)` → `incomingChannel.exit(code)` (lines 318-322).
- `resizePty` ← `session.on("window-change")` → `activeUpstreamChannel.setWindow(rows, cols, height, width)` (`gateway-server.ts:225`).
- signal ← `session.on("signal")` → `activeUpstreamChannel.signal(info.name)` (`gateway-server.ts:231`).
- `writeStdin` / stdout-stderr ← `pipeStreams(...)` (lines 273, 316, 362), which must stay binary-safe (Buffers, no UTF-8 mangling, no line buffering).

The plan requires deliberate process groups (plan §10.4), PTY master/slave allocation with a controlling terminal and correct foreground process group (plan §11), and is explicit that the daemon is **not** a terminal emulator — it captures and forwards PTY bytes (plan §11). PTY allocation works unprivileged via the `nix`/`rustix` term features already in `Cargo.toml` (brief §6).

## Decision

1. **Deliberate process groups.** Each managed command/session runs in its own process group (a fresh session leader for PTY sessions via `setsid`, a new pgid for non-PTY exec) so signals target the managed process tree rather than only the direct child (plan §10.4). `signalProcess`/`killProcess` and the cancellation sequence deliver signals to the process group, not a single PID.

2. **PTY master/slave with a controlling terminal.** For interactive sessions sealantd allocates a PTY master/slave pair (`openpty` via `rustix`/`nix`, unprivileged — brief §6), creates a new session, makes the slave the controlling terminal, and sets the spawned shell/command as the foreground process group of that terminal (plan §11). This makes terminal-generated signals (Ctrl-C → `SIGINT`, Ctrl-Z → `SIGTSTP`, etc.) behave correctly without sealantd interpreting keystrokes.

3. **Resize maps to `TIOCSWINSZ`.** `resizePty` services `gateway-server.ts:225`'s `setWindow(rows, cols, height, width)` and applies `TIOCSWINSZ` on the session PTY master, preserving the argument order the gateway forwards (rows, cols, then pixel height/width). The `{ cols, rows, width, height, modes }` supplied at `openSession` (`gateway-server.ts:248-257`) sets the initial window.

4. **SSH signal-name translation.** The signal handler servicing `gateway-server.ts:231` translates SSH signal names (e.g. `INT`, `TERM`, `KILL`, `HUP`, `QUIT`, `USR1`, `USR2`) to the corresponding OS signal numbers and delivers them to the session's process group. Unknown/unsupported names are rejected with a typed control error rather than silently dropped.

5. **Ownership boundary.** The ssh-gateway owns authentication and edge transport; sealantd owns the in-workspace PTY/process lifecycle (brief §3, plan §11). sealantd does not authenticate end users — it trusts the gateway's already-authenticated upstream connection (or, in the replacement model, the control-socket caller).

6. **Capture, not emulation.** sealantd captures PTY output and forwarded input as raw bytes (base64 with original byte count over the JSON wire — plan §4.5, §12) and forwards them; it does not parse escape sequences or maintain a screen model. It is not a terminal emulator (plan §11).

## Consequences

### Positive

- A single Ctrl-C / `SIGINT` reaches the whole foreground job (pipelines, subshells), matching operator expectations and avoiding orphaned children (plan §10.4).
- Interactive shells, pagers, REPLs, and full-screen TUIs work because they get a real controlling terminal with a correct foreground pgrp (plan §11).
- Binary-safe byte forwarding satisfies the gateway's `pipeStreams` contract (brief §3) and the plan's binary-safety rule (plan §4.5): no UTF-8 assumption, no line buffering, preserved chunk boundaries.
- Exec sessions surface real exit codes for `incomingChannel.exit(code)` (`gateway-server.ts:318-322`), which the delegated `workspace-ssh-shell` path cannot guarantee today.
- PTY works unprivileged, so the single musl linux/amd64 artifact runs under plain `docker run` across Fedora/Arch/Nix base images (brief §6).

### Negative

- sealantd must correctly manage controlling-terminal and foreground-pgrp transitions (`setsid`, `TIOCSCTTY`, `tcsetpgrp`), which are subtle and easy to get wrong; mis-sequencing causes "no controlling terminal" or job-control breakage. These paths are Linux-only and validated in docker (brief §6), not on the macOS dev host.
- SSH-name → OS-signal translation is an explicit mapping that must be kept complete; gaps surface as signals that the gateway forwards but the workload never receives.
- Capturing both directions of PTY traffic doubles the byte volume flowing through the telemetry pipeline for interactive sessions, increasing pressure on bounded queues and spill policy.
- Because sealantd is not an emulator, downstream consumers (SDK) must interpret raw byte streams themselves; sealantd offers no cooked/rendered view.

## Alternatives considered

- **Keep the upstream `sshd` PTY and have sealantd only observe.** Rejected: sealantd would not own `exec` exit codes, process-group signaling, or resize, and could not produce the trustworthy process/PTY evidence trail the plan requires (plan §10-§11). The brief is explicit that PTY/process ownership moves to sealantd (brief §3).
- **One process group per session leader only, signaling the direct child.** Rejected: signals would miss grandchildren (pipelines, background jobs), defeating process-tree cleanup (plan §10.4).
- **sealantd as a full terminal emulator (screen model, escape parsing).** Rejected as an explicit non-goal (plan §11, §20): it adds large surface area, risks divergence from the real terminal, and is unnecessary for a byte-faithful evidence trail.
- **Pass SSH signal names through unmapped.** Rejected: OS signal delivery requires numeric signals; an explicit, closed translation with a typed error on unknown names is auditable and fails loudly.
