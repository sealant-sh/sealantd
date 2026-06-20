# sealantd Known Limitations

This is the honest-capability register for sealantd. It enumerates what the
daemon **cannot** truthfully observe or guarantee, why the boundary exists, and
the concrete behaviour we ship instead. It is grounded in the honest-observability
constraints of plan §4.6 and the build/deploy constraints of the integration
brief §6. Every network-collector limitation maps to the `confidence` and
`captureMethod` event fields (plan §6, the `sealant-telemetry`/`sealant-network`
crates) — the rule is to record uncertainty, never to fabricate certainty.

Each entry is framed as **Limitation / Why / What we do instead**.

---

## Network observability (plan §4.6, §14)

These are governed by the closed `captureMethod` set (`metadata`, `proxy`,
`privileged`, plan §14) and an explicit `confidence` value on every emitted
event. The default unprivileged target is `metadata` + explicit `proxy`; the
`privileged` backends are off by default (see SEC limitations below).

### TCP metadata is addresses and ports, not encrypted application paths
- **Limitation.** For a raw TCP connection sealantd can record the destination
  address and port (and timing), but not the application-layer path, request, or
  payload once the stream is encrypted.
- **Why.** plan §4.6: "TCP metadata reveals addresses and ports, not encrypted
  application paths." Below the proxy layer there is no plaintext to read.
- **What we do instead.** Emit a `network` event via the `metadata`
  `captureMethod` carrying address + port + timing only, with `confidence`
  reflecting that this is connection metadata, not content. We do not synthesize
  a URL or body.

### DNS reveals queried names, and only those
- **Limitation.** DNS telemetry exposes queried names, not the eventual
  encrypted traffic to the resolved hosts, and not necessarily a 1:1 mapping
  from a query to the connection that uses it.
- **Why.** plan §4.6: "DNS telemetry may reveal queried names." A name resolved
  now may be connected to later, by a different process, or never.
- **What we do instead.** Record DNS observations where available (plan §14) as
  their own evidence with their own `confidence`; we correlate to connections
  only as a best-effort, time-windowed inference, never as an asserted link.

### An explicit HTTP proxy sees request metadata, not more
- **Limitation.** The explicit local egress proxy (`captureMethod: proxy`, plan
  §14, `sealant-network`) observes plaintext HTTP request metadata only for
  traffic that actually routes through it and is unencrypted at that hop.
- **Why.** plan §4.6: "An explicit HTTP proxy can observe request metadata." It
  cannot see traffic that bypasses it or that is already encrypted.
- **What we do instead.** Capture observable HTTP/CONNECT request metadata at
  the proxy with high `confidence` for the proxied hop, and make no claim about
  traffic that did not transit the proxy.

### HTTPS CONNECT reveals host + port, not the encrypted URL or body
- **Limitation.** For tunneled HTTPS, the proxy sees the `CONNECT host:port`
  target but not the encrypted URL path, headers, or body inside the tunnel.
- **Why.** plan §4.6: "HTTPS CONNECT normally reveals destination host and port,
  not encrypted URL paths or bodies." TLS terminates past the proxy.
- **What we do instead.** Per plan §14, record destination host and port for the
  CONNECT without pretending the encrypted path is known. The event carries the
  tunnel target; the URL/body fields are absent, not guessed.

### Per-process network attribution is unreliable without privilege
- **Limitation.** Tying a specific connection to a specific sealantd
  `ProcessId` is best-effort under the default unprivileged model.
- **Why.** plan §4.6: "Process attribution for network traffic may require eBPF,
  cgroup hooks, netlink, or privileged access." Brief §6: containers run via
  plain `docker run`; syscall-level capture (eBPF/ptrace) needs capabilities the
  blueprint→adapter path does not convey today.
- **What we do instead.** Emit network events with `captureMethod: metadata`/`proxy`
  and a `confidence` that honestly reflects inferred attribution; when a
  connection cannot be attributed to a `ProcessId` we say so rather than picking
  one. The optional `privileged` backends (eBPF, cgroup socket hooks,
  netlink/conntrack, transparent proxy, plan §14) are an investigation track,
  not the default, and remain gated on capabilities.

---

## Filesystem observability (plan §4.6, §13)

### inotify can overflow and lacks perfect process attribution
- **Limitation.** The inotify-based fs collector (`sealant-fs`) can miss events
  under queue overflow and cannot reliably name the process that caused a change.
- **Why.** plan §4.6: "Inotify can overflow and does not provide perfect process
  attribution." plan §13 explicitly states: do not claim reliable per-process
  attribution from inotify alone.
- **What we do instead.** Mark fs events with `captureMethod: inotify` and a
  `confidence` that signals best-effort; surface overflow as an observable
  condition rather than silently dropping it; do not attach a `ProcessId` to an
  fs change unless an independent signal supports it. Snapshot-based capture
  (`captureMethod: snapshot`) is the fallback when continuous watching is
  insufficient.

---

## I/O ordering (plan §4.6)

### Separate stdout/stderr pipes give no perfect cross-stream causal order
- **Limitation.** stdout and stderr arrive on separate pipes; their relative
  ordering as observed by sealantd does not establish the true causal order in
  which the process wrote them.
- **Why.** plan §4.6: "Separate stdout and stderr pipes do not establish perfect
  causal ordering across streams." Two kernel pipe buffers drain independently.
- **What we do instead.** Each I/O event carries a per-stream monotonic
  `StreamOffset`, so ordering *within* a single stream is exact. Final `Sequence`
  values are assigned at one deterministic point per runtime, giving a stable
  total order of record — but we treat cross-stream interleave as the daemon's
  observation order, not a claim about the process's write order. Bytes travel as
  base64 with an original byte count (never assumed UTF-8), so chunk content and
  boundaries are preserved exactly even when cross-stream causality cannot be.

---

## Environment and packaging (brief §6)

### amd64 first; arm64 is not a supported target yet
- **Limitation.** sealantd ships a `linux/amd64` artifact only.
- **Why.** Brief §6: builds are effectively amd64 (`--platform linux/amd64` is
  added only for Arch in `buildkit-builder.ts:1124`; Fedora and Nix inherit host
  arch). arm64 needs a cross-compiled binary plus a blueprint arch field that
  does not exist.
- **What we do instead.** Ship amd64 now; defer arm64 until the build matrix and
  blueprint arch field land. (REQ-PKG.)

### Single statically-linked musl binary, no dynamic distro libs
- **Limitation.** sealantd is one self-contained static musl binary, not a
  glibc/dynamically-linked build tuned per base image.
- **Why.** Brief §6: three base images — Fedora (glibc), Arch (glibc), and
  `nixos/nix` (non-FHS, no `/usr/sbin`). A glibc binary risks breaking on the Nix
  image's nonstandard layout; a single static musl binary is the only safe
  single-artifact path across all three.
- **What we do instead.** Build static musl, depend on no distro shared
  libraries, and own a writable runtime dir (analogous to today's
  `$SSH_RUNTIME_DIR`) for the `0600` Unix socket. PTY allocation
  (`openpty`/`TIOCSWINSZ` via nix/rustix) works unprivileged, so the core
  process/PTY path needs no elevated capabilities. (REQ-PKG / REQ-PTY.)

### eBPF/ptrace capabilities are not conveyed by the blueprint→adapter path
- **Limitation.** Syscall-level instrumentation (eBPF programs, ptrace) is not
  available in the default container.
- **Why.** Brief §6: containers launch via plain `docker run`; the capabilities
  eBPF/ptrace require are not conveyed by the blueprint→adapter path today
  (only `DockerRuntimeAdapter` is functional; k8s/k3s throw).
- **What we do instead.** Favor in-process instrumentation (pipes, PTY, explicit
  proxy, inotify, snapshots) as the default capture surface. The privileged
  network backends (plan §14) stay behind a capability gate and degrade to
  honest `metadata`/`proxy` capture when capabilities are absent. (REQ-SEC.)

### TLS interception is off by default and needs a separate privacy review
- **Limitation.** sealantd does not intercept/decrypt TLS by default; the
  explicit proxy sees only CONNECT metadata for HTTPS (see network section).
- **Why.** Brief §6 + plan §4.6: decrypting TLS is a transparent-proxy/MITM
  capability with material privacy and trust implications, separate from the
  daemon's evidence-trail mandate.
- **What we do instead.** Keep TLS interception off by default. Any transparent
  proxy / TLS-termination backend is an opt-in feature gated behind a separate
  privacy review and the capability requirements above — not part of the default
  honest-observability posture. (REQ-SEC / REQ-NET.)

### PID-reuse signalling uses a documented fallback, not pidfd (yet)
- **Limitation.** Process signalling targets the OS process group via `killpg`
  rather than a `pidfd`, so there is a theoretical PID/PGID-reuse race.
- **Why.** pidfd is Linux-only and the dev host is macOS; the cross-platform path
  must work everywhere. Plan §10.4 explicitly permits "a documented safe fallback".
- **What we do instead.** We only signal while the managed process is in a *live*
  state, and the owning Tokio task holds the `Child` (and therefore the unreaped
  pid) until it publishes `process.exited` — so the pid is not reaped, and thus not
  reusable, underneath a signal. The window between kernel exit and Tokio's reap is
  sub-millisecond and a group-leader pgid reuse within it is vanishingly unlikely.
  `process.started.pidfd` and `capabilities.features.pidfd` report `false` until a
  Linux pidfd path lands (ADR-0006). (REQ-PROC, Phase 2.)

### Adopted-orphan reaping is registry-guarded (not a global waitpid)
- **Limitation.** A naive global `waitpid(-1)` reaper would steal the children Tokio
  owns and reaps itself, corrupting managed-process results.
- **Why.** Tokio already reaps its own children; a second unconditional reaper races it.
- **What we do instead (implemented, Linux).** The daemon sets
  `PR_SET_CHILD_SUBREAPER` so double-forked orphans reparent to it, and a
  SIGCHLD-driven reaper uses `waitid(…, WNOWAIT)` to *peek* each waitable child:
  Tokio-owned pids (present in the process registry) are left for Tokio, and only
  genuine adopted orphans are reaped via `waitpid`. A 2 s sweep catches anything
  queued behind a Tokio-owned zombie. This also covers the **PID 1** case (daemon as
  container init). Validated by `crates/sealant-process/tests/orphan_reaping.rs`
  (run on Linux via `scripts/linux-test.sh`). (REQ-PROC, ADR-0006.)
