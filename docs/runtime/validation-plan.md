# sealantd Validation Plan

Grounded in `plan.html` §22–§25 and `docs/runtime/integration-brief.md`. This plan defines the loop, commands, adversarial matrix, soak checklist, and per-phase exit gates that gate every commit. A requirement is not complete because code exists; it is complete when observable behavior matches the contract under normal, failure, and shutdown scenarios (plan §23 callout).

## Platform constraint: Linux-only behaviors validated in Docker from a macOS dev host

The dev host is macOS; the ship target is a single statically-linked musl `linux/amd64` binary that must run unprivileged on the `fedora:41`, `archlinux`, and `nixos/nix` base images (brief §6, REQ-PKG-*). The following behaviors are Linux-only and have **no faithful macOS equivalent**, so they are validated exclusively inside Docker containers launched from the macOS host (rootless `docker run` for the default path, privileged for capability-gated collectors):

- **`pidfd`** for PID-reuse-safe process operations (plan §22 Phase 2 gate "PID-reuse-sensitive operations use pidfds or a documented safe fallback").
- **`inotify`** for the filesystem live watcher and overflow handling (plan §22 Phase 5; brief §4 notes no fs tables exist today).
- **PTY controlling terminal (`ctty`) / `TIOCSWINSZ`** session ownership taken over from the in-container sshd (brief §3; REQ-PTY-* mapping `setWindow(rows, cols, height, width)` → `TIOCSWINSZ`).
- **Namespaces / subreaper / PID 1 reaping** for grandchild cleanup (plan §22 Phase 2 gate "subreaper/PID 1 behavior").

macOS builds compile cross-platform and run platform-agnostic unit tests (protocol framing, sequencing, base64 codec); anything touching the above runs under `cargo test`/integration harnesses **inside a Linux container**, never natively on the host.

## 1. The validation loop (plan §23, 12 steps)

Run end-to-end per behavior. Steps 5–8 and 10–12 are the acceptance gate.

| # | Step | Concrete sealantd binding |
|---|------|---------------------------|
| 1 | Define one concrete behavior + its acceptance test | One REQ-`<AREA>`-`<n>` ↔ one TST-`<AREA>`-`<n>` |
| 2 | Update the typed protocol and requirement matrix | Edit serde structs (single schema source); regenerate JSON Schema → TS types (brief §5, `@sealant/runtime-protocol`) |
| 3 | Write focused tests before/alongside implementation | Rust unit + a TS contract test for any wire-facing change |
| 4 | Implement the smallest complete vertical slice | One crate of `crates/*` plus its TS surface |
| 5 | Run formatting, linting, unit, and type checks | `cargo fmt --check`, `cargo clippy … -D warnings`, `cargo test --workspace`, `pnpm typecheck` (tsgo) |
| 6 | Run subsystem integration tests | Per-crate integration (e.g. sealant-process, sealant-pty) |
| 7 | Run container-level tests | Rootless `docker run` against the musl binary on fedora/arch/nix images |
| 8 | Inject realistic failures | Slow/disconnected sink, disk-full, truncated spool, missing capabilities |
| 9 | Request an independent high-risk review where appropriate | unsafe code, reaping, signal handling, frame decoder |
| 10 | Fix all blocking findings | — |
| 11 | Update architecture, protocol, limitations, requirement status | ADRs in `docs/adr`, this matrix |
| 12 | Commit only after the acceptance gate passes | — |

## 2. Quality command list (plan §23)

```
# Rust workspace
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace

# TypeScript (packages/*, brief §5: source-exported, no build step)
pnpm typecheck            # tsgo -p tsconfig.json --noEmit
pnpm test                 # vitest unit tests

# Cross-language contract tests
#   Rust serde structs -> schemars JSON Schema -> generated TS types;
#   round-trip golden frames in BOTH languages so @sealant/runtime-client
#   decodes exactly what sealantd encodes (length-prefixed JSON, 4-byte BE
#   length, base64 bytes + original byte count; brief wire-protocol facts).

# Container integration (launched from the macOS dev host)
docker run  --rm ...      # ROOTLESS: default path on fedora:41 / archlinux / nixos/nix
docker run  --privileged  # PRIVILEGED: capability-gated network collector,
                          #             ptrace/eBPF paths (plan §22 Phase 6)
```

Additional tools where appropriate (plan §23): Miri for unsafe-adjacent pure Rust; Loom/model-based tests for concurrency-sensitive state (registry, sequencer, spool); fuzzing for the **frame decoder, spool/log parsers, and untrusted control frames**; coverage, `cargo audit`, license checks; `strace -ff`, `/proc`, `ps`, `lsof` inside the container; sanitizer-compatible builds where practical.

Both rootless and privileged runs are **mandatory** (plan §23 quality block lists them separately, plan §26 "Rootless and privileged test results"). The default sealantd path must pass rootless; privileged runs only exercise the capability-gated network backend (brief §6: eBPF/ptrace need capabilities the blueprint→adapter path does not convey today, so favor in-process instrumentation and prove graceful degradation when capabilities are absent).

## 3. Adversarial test matrix (plan §24)

Each row is `scenario → expected behavior`, keyed by a TST id. AREA codes: PROC, PTY, IO, SPOOL, FS, NET, SEC.

### 3.1 Process (PROC) — plan §24 "Process tests"

| Test ID | Scenario | Expected behavior |
|---|---|---|
| TST-PROC-1 | Command not found | Structured spawn error event (not a crash); closed error-code set; no ProcessId leaked |
| TST-PROC-2 | Immediate exit; exit 0; exit 42 | Exit event carries real code; gateway `incomingChannel.exit(code)` path reports it (brief §3) |
| TST-PROC-3 | Killed by SIGTERM / SIGKILL | Termination recorded with signal; ExecutionId resolved, no zombie |
| TST-PROC-4 | Child ignores SIGTERM | SIGTERM→SIGKILL escalation fires after timeout (Phase 2 gate) |
| TST-PROC-5 | Child spawns grandchildren | Whole process group tracked; killed on shutdown |
| TST-PROC-6 | Double-fork / adopted descendant | Subreaper (PID 1) reaps adopted descendants; no orphans (Linux/Docker only) |
| TST-PROC-7 | Grandchild inherits stdout/stderr descriptors | Output still attributed; descriptors not leaked beyond intent |
| TST-PROC-8 | Large stdout / large stderr | Bounded memory; backpressure, no unbounded buffering |
| TST-PROC-9 | Concurrent stdout + stderr | Per-stream monotonic streamOffset preserved; no interleave corruption |
| TST-PROC-10 | NUL bytes / invalid UTF-8 | Round-trips via base64 + original byte count; never assumed UTF-8 (brief wire facts) |
| TST-PROC-11 | stdin close / broken pipe | EPIPE handled; no panic; event emitted |
| TST-PROC-12 | Timeout / runtime shutdown during execution | Process torn down deterministically; final exit/abort event emitted |
| TST-PROC-13 | PID reuse risk / zombie detection | pidfd-based identity (Linux); OS PID never used as stable ProcessId (brief identifiers) |

### 3.2 PTY (PTY) — plan §24 "PTY tests"

| Test ID | Scenario | Expected behavior |
|---|---|---|
| TST-PTY-1 | Interactive shell | SessionId minted; shell attached to a real ctty (Linux/Docker only) |
| TST-PTY-2 | Echoed and raw input | Terminal modes from `{cols,rows,width,height,modes}` applied exactly (brief §3) |
| TST-PTY-3 | ANSI / binary-safe output | Bytes pass through unmodified (base64 transport), no line buffering |
| TST-PTY-4 | Full-screen terminal application | Renders correctly; window geometry honored |
| TST-PTY-5 | Resize | `setWindow(rows,cols,height,width)` → `TIOCSWINSZ` on session PTY (brief §3, Linux only) |
| TST-PTY-6 | Ctrl+C / terminal signal behavior | SSH signal name → OS signal to foreground process group (brief §3) |
| TST-PTY-7 | Session close / unexpected child exit | PTY fd + slave released; resources freed after normal AND abnormal exit (Phase 3 gate) |
| TST-PTY-8 | Proxy disconnect | Daemon detects gateway disconnect, tears down session, no leaked master |
| TST-PTY-9 | Recording and replay | Recorded input/output replay is binary-safe and offset-ordered |

### 3.3 Telemetry / Spool (IO, SPOOL) — plan §24 "Telemetry and spool tests"

| Test ID | Scenario | Expected behavior |
|---|---|---|
| TST-SPOOL-1 | Slow sink / disconnected sink | Bounded queues; resident memory stays bounded (Phase 4 gate) |
| TST-SPOOL-2 | Queue full / spool full | Backpressure or explicit drop event; never silent for critical events |
| TST-SPOOL-3 | Disk full / permission failure | Degradation event emitted; daemon survives |
| TST-SPOOL-4 | Corrupt / truncated records | Deterministic outcome; bad record skipped, position advanced |
| TST-SPOOL-5 | Duplicate delivery / restart replay | At-least-once with idempotent EventId; restart replays only unacknowledged events |
| TST-IO-1 | Sequence ordering and gaps | Sequence assigned at ONE deterministic point per runtime; gaps detectable |
| TST-SPOOL-6 | Drop reporting / critical-event preservation | Drops are reported as events; critical events never silently lost (Phase 4 gate) |

### 3.4 Filesystem (FS) — plan §24 "Filesystem tests"

| Test ID | Scenario | Expected behavior |
|---|---|---|
| TST-FS-1 | Create / modify / delete / rename | Each case yields correct diff vs baseline snapshot (inotify, Linux/Docker only) |
| TST-FS-2 | Directory create / delete | Directory events captured and coalesced |
| TST-FS-3 | Symlink / symlink loop | Loops terminated; symlink represented honestly, no infinite walk |
| TST-FS-4 | Large and binary files | Content handled by reference/metadata; bytes binary-safe |
| TST-FS-5 | Ignore rules | Ignored paths excluded from final diff |
| TST-FS-6 | Editor temp-file save pattern | Atomic-rename temp files normalized to the logical edit (Phase 5 gate) |
| TST-FS-7 | Watcher overflow | Overflow emits an event and triggers a rescan (Phase 5 gate) |
| TST-FS-8 | Path traversal / workspace escape | Events outside the workspace boundary rejected; no escape |

### 3.5 Network (NET) — plan §24 "Network tests"

| Test ID | Scenario | Expected behavior |
|---|---|---|
| TST-NET-1 | DNS lookup | Query/response captured; hostname recorded |
| TST-NET-2 | HTTP request | Request metadata captured in the active mode |
| TST-NET-3 | HTTPS CONNECT | CONNECT target captured without breaking TLS |
| TST-NET-4 | TCP / UDP traffic | Connection-level evidence for both transports |
| TST-NET-5 | Connection failure | Failure recorded; no daemon crash |
| TST-NET-6 | Proxy bypass attempt | Bypass detected/represented honestly, not silently dropped |
| TST-NET-7 | Missing Linux capabilities | Daemon degrades to metadata mode; never crashes (Phase 6 gate); privileged-only path skipped rootless |
| TST-NET-8 | Privileged collector startup failure | Falls back to degraded mode; emits capability event (privileged Docker run) |
| TST-NET-9 | Source normalization / unknown hostname | Attribution uncertainty represented honestly (Phase 6 gate) |
| TST-NET-10 | Multiple IPs for one host | All resolved IPs attributed to the host without collapsing |

### 3.6 Security (SEC) — plan §24 "Security tests"

| Test ID | Scenario | Expected behavior |
|---|---|---|
| TST-SEC-1 | Child reads daemon environment | Daemon secrets not present in child env (Phase 7 gate; env isolation) |
| TST-SEC-2 | Child accesses the control socket | `0600` socket rejects unauthorized peers; peer validation enforced (REQ-CTRL/SEC) |
| TST-SEC-3 | Child signals the daemon | Daemon ignores/refuses unauthorized signals; stays alive |
| TST-SEC-4 | Child attempts ptrace | Blocked where applicable; documented if capability unavailable |
| TST-SEC-5 | Oversized / malformed control frames | Max frame size enforced **before allocation**; frame rejected, connection survives (wire facts) |
| TST-SEC-6 | Invalid path / signal input | Validated against closed sets; rejected with typed error |
| TST-SEC-7 | Secret-like output redaction | Redaction applied to matching output |
| TST-SEC-8 | Runtime-only environment leakage | Runtime-only env never leaked to managed processes or inherited fds |
| TST-SEC-9 | Excessive forks / output / file events | Limits enforced; daemon stays bounded under fork/output/event floods |

Phase 7 gate also requires: protocol and spool **fuzzers find no obvious crashes** (covers TST-SEC-5 + spool decoder).

## 4. Soak / performance checklist (plan §25)

Repeatable measurements, not speculative claims. Each runs inside a Linux container; record CPU, memory, disk, queue depth, and latency with the **exact configuration used**.

- [ ] Stream a large amount of stdout to a **fast** sink.
- [ ] Repeat with a deliberately **slow** sink.
- [ ] Verify resident memory remains bounded (ties to TST-SPOOL-1, Phase 4 gate).
- [ ] Run many concurrent short-lived processes.
- [ ] Run multiple long-lived PTY sessions.
- [ ] Generate filesystem-event bursts and watcher overflow (ties to TST-FS-7).
- [ ] Generate many network connections.
- [ ] Exercise spool rotation and replay over an extended run.
- [ ] Repeatedly shut down under active load (ties to Phase 2/3 shutdown gates).
- [ ] Record CPU, memory, disk, queue, and latency with the exact configuration → benchmark and soak report (plan §26).

## 5. Per-phase exit gates (plan §22, Phases 0–8)

A phase closes only when **every** gate item below is demonstrably met under normal, failure, and shutdown scenarios.

### Phase 0 — Discovery and architecture
- [ ] Every requirement (REQ-`<AREA>`-`<n>`) has an owner and a test strategy.
- [ ] Rust and TypeScript agree on **protocol version 1** (the versioned handshake; brief §5 REQ-PROTO-11 — no negotiation exists today and must be designed).
- [ ] No major subsystem lacks an explicit failure policy.

### Phase 1 — Small end-to-end vertical slice
- [ ] TypeScript starts the daemon, executes one non-PTY command, streams events, receives the correct result, and shuts it down (`@sealant/runtime-client`).
- [ ] Invalid UTF-8 and NUL bytes round-trip correctly (base64 + byte count; TST-PROC-10).
- [ ] Protocol output is never mixed with diagnostics (length-prefixed JSON frames only on the socket; tracing goes elsewhere).

### Phase 2 — Correct process lifecycle
- [ ] No zombies or managed-process orphans in the process matrix (TST-PROC-3/5/6).
- [ ] `SIGTERM` escalation works (TST-PROC-4).
- [ ] PID-reuse-sensitive operations use **pidfds** or a documented safe fallback (Linux/Docker; TST-PROC-13).
- [ ] Runtime shutdown works with active process trees (TST-PROC-12).

### Phase 3 — PTY and session runtime
- [ ] Interactive shell and a full-screen application work (TST-PTY-1/4).
- [ ] Resize propagates correctly (TST-PTY-5, `TIOCSWINSZ`).
- [ ] Input/output replay is binary-safe (TST-PTY-9).
- [ ] Resources released after normal and abnormal exits (TST-PTY-7/8).

### Phase 4 — Durable telemetry pipeline
- [ ] Slow sinks do not create unbounded memory growth (TST-SPOOL-1, §4 soak).
- [ ] Restart replays unacknowledged events safely (TST-SPOOL-5).
- [ ] Corrupt and partial records are deterministic (TST-SPOOL-4).
- [ ] Critical event loss is never silent (TST-SPOOL-6).

### Phase 5 — Filesystem telemetry
- [ ] Create/modify/delete/rename cases pass (TST-FS-1, inotify Linux/Docker).
- [ ] Editor temp-file patterns normalized reasonably (TST-FS-6).
- [ ] Overflow emits an event and triggers a rescan (TST-FS-7).
- [ ] Symlink and path-boundary tests pass (TST-FS-3/8).

### Phase 6 — Network telemetry
- [ ] Local DNS, HTTP, HTTPS CONNECT, TCP, and UDP fixtures produce correct evidence (TST-NET-1..4).
- [ ] Attribution uncertainty is represented honestly (TST-NET-9/10).
- [ ] Missing privilege never crashes the daemon (TST-NET-7/8; rootless run must pass, privileged run validates the gated backend).

### Phase 7 — Security and hardening
- [ ] Threat-model tests pass (TST-SEC-1..4, §3.6).
- [ ] Daemon secrets do not leak through env or inherited descriptors (TST-SEC-1/8).
- [ ] Unauthorized clients are rejected (TST-SEC-2, `0600` socket peer validation).
- [ ] Protocol and spool fuzzers find no obvious crashes (TST-SEC-5 + spool decoder).

### Phase 8 — Packaging and final integration
- [ ] Multi-arch artifact: single statically-linked musl `linux/amd64` binary runs unprivileged on `fedora:41`, `archlinux`, `nixos/nix` (REQ-PKG-*, brief §6) from one image, no distro-specific dynamic libs.
- [ ] BuildKit stage copies `sealantd` and starts it before the harness foreground command (brief §6, `buildkit-builder.ts`).
- [ ] `@sealant/runtime-protocol` / `@sealant/runtime-client` package, examples, and operational docs delivered.
- [ ] Benchmark and soak report (§4) plus complete requirements traceability (every REQ ↔ TST ↔ phase).
