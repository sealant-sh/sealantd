# ADR-0006: pidfd, subreaper, and PID 1 strategy

## Status

Accepted, 2026-06-20

## Context

sealantd is launched from the image entrypoint (`renderWorkspaceEntrypoint`, `buildkit-builder.ts` ~lines 819-840) and takes over the foreground PTY/process lifecycle that the upstream `sshd`/`workspace-ssh-shell` owns today (brief §1, §3). Depending on how the entrypoint is structured, sealantd may run as the container's PID 1, or as a child under a thin init — both must be handled. Workspace workloads can be buggy, hostile, evasive, or resource-exhausting (plan §18), and they routinely spawn deep process trees (shells, build tools, agents, dev servers) that detach and orphan descendants.

The plan mandates, under process groups / pidfds / subreaping / PID 1 (plan §10.4):

- Investigate Linux pidfds to reduce PID-reuse races, with a documented fallback.
- Investigate `PR_SET_CHILD_SUBREAPER` to adopt and reap orphaned descendants.
- If the daemon may run as PID 1, implement PID 1 signal handling and child reaping correctly.
- Use close-on-exec on daemon-only descriptors (also a stated security goal, plan §18).

The shutdown sequence depends on this: it must reap direct **and adopted** descendants and emit final lifecycle/telemetry-loss events (plan §10.5, steps 6-8). The target is Linux-first; the dev host is macOS, so Linux-only syscalls are built cross-platform but validated only inside docker containers (brief §6). The daemon must run from a single statically-linked musl linux/amd64 artifact across Fedora/Arch/Nix base images (brief §6), so feature use must be runtime-detected, not assumed from build-time libc.

## Decision

1. **pidfd where available, documented waitpid fallback.** When the kernel supports it, sealantd obtains a `pidfd` for each spawned child (via `clone3`/`pidfd_open` through `rustix`/`nix`) and uses it for signaling (`pidfd_send_signal`) and exit notification. The pidfd refers to a specific process, eliminating the PID-reuse race where a recycled PID is signaled after the original child exited. The OS PID is never the stable product-level `ProcessId` (plan §8.3); pidfd, PID, and PGID are recorded as separate metadata on the managed process record (plan §10.2). Where pidfd is unavailable (older kernel, detection fails), sealantd falls back to `waitpid`-based reaping with PID held only until reap, and this fallback is recorded as a capability so the limitation is visible (plan §6 requirements matrix, plan §17 capabilities).

2. **`PR_SET_CHILD_SUBREAPER` to adopt orphans.** Early in startup sealantd sets `PR_SET_CHILD_SUBREAPER` so that descendants which re-parent away from their immediate parent are re-parented to sealantd instead of to init. This lets the daemon observe and reap orphaned descendants and complete the shutdown reap step (plan §10.4, §10.5). Adopted processes are reaped and accounted; where attribution back to a managed `ProcessId` is uncertain, events carry that uncertainty (consistent with the plan's honest-observability stance, plan §4.6).

3. **Correct PID 1 behavior when running as PID 1.** sealantd detects whether it is PID 1 and, when it is, installs proper init signal handling (forwarding/handling `SIGTERM`/`SIGINT` for orderly shutdown) and a reaping loop that harvests **all** terminated children — including the indirect orphans the kernel re-parents to PID 1 — so the container does not accumulate zombies. PID 1 also has no default signal dispositions, which is handled explicitly rather than relying on kernel defaults.

4. **Close-on-exec on daemon-only descriptors.** The control Unix socket (`/run/sealantd.sock`, perms `0600` — brief §1, §6), spool file descriptors, and any internal pipes/eventfds are opened `O_CLOEXEC` (or have `FD_CLOEXEC` set) so spawned workloads never inherit them. This satisfies the security goal (plan §18) and prevents fake-telemetry injection and control-socket leakage into child processes.

5. **Linux-only, validated in docker.** pidfd, `PR_SET_CHILD_SUBREAPER`, and PID 1 reaping are Linux-only. They compile cross-platform (the macOS dev host builds the workspace) but are exercised and validated only in Linux docker containers (brief §6). Kernel-feature presence is detected at startup and reported through capabilities/health (plan §17), not assumed.

## Consequences

### Positive

- pidfd removes the PID-reuse window, so `signalProcess`/`killProcess` and the cancellation sequence (plan §10.5) cannot accidentally signal an unrelated recycled process.
- Subreaping plus PID 1 reaping means deep, detaching process trees are fully accounted and reaped; no zombies accumulate and the shutdown reap step is real (plan §10.4, §10.5).
- A documented `waitpid` fallback keeps the single musl binary working on older Linux kernels across all three base images (brief §6) while reporting the degraded capability honestly (plan §6, §17).
- Close-on-exec keeps the control socket and spool descriptors out of untrusted workloads, closing a tampering/leak vector in the threat matrix (plan §18).

### Negative

- pidfd vs. waitpid is two code paths with different exit-notification mechanics; both must be tested, and the fallback path carries the PID-reuse risk the primary path avoids.
- Subreaper adoption means sealantd receives `SIGCHLD` for processes it did not directly spawn; attributing these adopted exits back to a managed `ProcessId` is best-effort and sometimes impossible, which must be surfaced rather than guessed (plan §4.6).
- PID 1 duties (signal forwarding, exhaustive reaping) add init-level responsibilities and failure modes that do not exist when sealantd runs as a normal child; getting them wrong can hang container shutdown.
- The most safety-critical paths cannot be validated on the macOS dev host and require docker-based Linux CI to exercise (brief §6), lengthening the validation loop.

## Alternatives considered

- **Plain `waitpid` on PIDs only, no pidfd.** Rejected as the primary mechanism: it reintroduces the PID-reuse race the plan calls out (plan §10.4). Retained only as the documented fallback when pidfd is unavailable.
- **No subreaper; rely on init to reap orphans.** Rejected: orphaned descendants would re-parent away from sealantd, making them invisible to the evidence trail and unreapable by the daemon, breaking the shutdown reap requirement (plan §10.5).
- **Assume sealantd is never PID 1.** Rejected: the entrypoint may start sealantd as PID 1 (brief §1), and ignoring that case leaves zombies and broken shutdown signaling in exactly that configuration.
- **External `tini`/`dumb-init` as PID 1, sealantd as a child.** Viable but adds a second binary to every image and a moving part across the Fedora/Arch/Nix layouts (Nix is non-FHS — brief §6); handling PID 1 correctly inside the single musl artifact keeps the one-artifact deployment promise (brief §6) and avoids depending on a distro-provided init.
- **Build-time libc feature assumptions for pidfd/subreaper.** Rejected: the artifact is one static musl binary shared across kernels (brief §6); runtime detection with capability reporting (plan §17) is required for honest behavior.
