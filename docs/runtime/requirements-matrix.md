# sealantd Requirements Traceability Matrix

This is the spine document for sealantd (plan §6). Every responsibility in the plan
appears as at least one row here so design, implementation, and validation stay
traceable. Requirements are grouped by AREA; IDs are `REQ-<AREA>-<n>` and reference
tests as `TST-<AREA>-<n>`. Priority is Must / Should / Later. The codebase is
greenfield — every crate under `crates/*/src/lib.rs` is a one-line doc stub today and
`packages/` does not yet exist (integration-brief §status note) — so **Status is
"Designed" for every row**. Owning crates follow the workspace shape in plan §7.

Each row's "Requirement" expands the brief's 15 numbered requirements (integration-brief
§7) and the plan responsibilities (§8–§20). "Capability/Privilege" records what the
Linux/namespace environment must provide; "Known limitations" prevents overclaiming
(plan §4.6, §6). Linux-first target; macOS is a build host only and Linux-only paths are
validated in docker containers.

---

## Implementation status log

Statuses below are updated as phases complete (plan §22). The per-row `Status` cells were authored
at "Designed"; this log records movement to Implemented / Validated.

**Phase 0 — Discovery & architecture (complete).** Monorepo discovery (`integration-brief.md`),
this matrix, `architecture.md`, `threat-model.md`, `validation-plan.md`, `known-limitations.md`, and
ADRs 0001–0011. The `sealant-protocol` crate realizes the wire contract: REQ-PROTO-1..6
**Implemented & Validated** (17 unit tests incl. flatten/round-trip/binary-safety;
`cargo run -p sealant-protocol --example dump-schema` emits the JSON Schema bundle).

**Phase 1 — End-to-end vertical slice (complete; exit gate met).** Implemented & Validated:
- **PROTO**: length-prefixed framing + full envelope/command/error model (`sealant-protocol`).
- **CTRL-1..4**: Unix socket + stdio transport, dispatch, one-ack contract, error-code union, stale-socket safety, `0600` perms (`sealant-control`, 6 tests).
- **CFG-1,2,3**: validated config, sanitized summary, deterministic config hash, bounded limits (`sealant-runtime-core`, 11 tests).
- **PROC**: `exec` with own process group, lifecycle state machine, timeout→SIGTERM→SIGKILL escalation, signal/kill, process-tree cleanup on shutdown (`sealant-process`, 7 tests).
- **IO-1**: binary-safe stdout/stderr capture as base64 `io.chunk` with per-stream offsets — NUL + non-UTF-8 round-trip proven in Rust **and** TypeScript e2e.
- **PIPE (partial)**: bounded broadcast event bus with single-point sequence assignment (`sealant-telemetry`, 2 tests). Durable spool/retry/backpressure deferred to Phase 4.
- **HEALTH-1**: runtime states, heartbeats-after-validation, health/capabilities/metrics reports.
- **TS-1 (partial)**: `@sealant/runtime-client` + `@sealant/runtime-protocol` drive the daemon end-to-end (3 Node e2e tests). Effect-Schema codegen from JSON Schema deferred to Workflow 7.
- **PKG (partial)**: `sealantd` (`--version/--check-config/--print-capabilities/--stdio`) + `sealantctl`. Static-musl multi-arch build deferred to Phase 8.

Exit gate (plan §22 Phase 1): TS starts the daemon, execs, streams events, gets the result, shuts
down ✅; invalid UTF-8 / NUL round-trip ✅; protocol output never mixed with diagnostics ✅
(`crates/sealantd/tests/e2e.rs`, `packages/runtime-client/test/e2e.test.ts`).

**Phase 2 — Correct process lifecycle (complete; exit gate met).** Development moved Linux-first
(the binary only runs in Linux containers); `scripts/linux-test.sh` is the authoritative gate and
**52 tests pass on linux/amd64**. Implemented & Validated:
- **PROC adversarial matrix** (plan §24): stdin streaming, grandchild/orphan reaping via
  process-group kill, SIGTERM-ignore → SIGKILL escalation, concurrent stdout/stderr, large-output
  chunking with contiguous offsets, command-not-found, nonzero exit, timeout.
- **PROC-6 subreaper + reaping**: `PR_SET_CHILD_SUBREAPER` + a SIGCHLD-driven, registry-guarded
  orphan reaper (`waitid(WNOWAIT)` peek; never steals Tokio-owned children; 2 s sweep) — covers
  double-fork adopted descendants and the PID-1 (container init) case
  (`crates/sealant-process/tests/orphan_reaping.rs`).
- **pidfd**: kernel capability detected (`/proc/sys/kernel/osrelease` ≥ 5.3) and reported in
  `capabilities.features.pidfd`/`subreaper`; signalling still uses `killpg` while the process is
  live (documented PID-reuse-safe fallback, plan §10.4). `process.started.pidfd` stays `false` until
  per-process pidfd signalling lands.

Exit gate (plan §22 Phase 2): no zombies/managed-orphans ✅; SIGTERM escalation ✅; PID-reuse ops use
pidfd-or-documented-fallback ✅; shutdown works with active process trees ✅.

Still **Designed-only** (future phases): PTY/sessions (PTY-*), durable spool/retry (SPOOL-*, PIPE
durability), filesystem telemetry (FS-*), network telemetry (NET-*), security hardening
(SEC-*: peer-cred validation, capability drop, fuzzers). Optional: per-process pidfd signalling,
resource sampling.

---

## PROTO — Wire protocol, framing, identifiers, events

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-PROTO-1 | Frame every message as a 4-byte big-endian length prefix + JSON body; never assume one `read()` is one message; enforce the configurable max frame size **before** allocating the body (plan §8.1, brief §7.11). | Must | sealant-protocol | Designed | TST-PROTO-1, TST-SEC-3 | None | JSON developer mode is verbose; protobuf deferred to an ADR (plan §8.2). |
| REQ-PROTO-2 | Rust serde structs are the single schema source; `schemars` emits JSON Schema that generates the TS types in `@sealant/runtime-protocol` (plan §5, §8.2, §19). | Must | sealant-protocol | Designed | TST-PROTO-2, TST-TS-1 | None | Generation drift caught only if contract tests (TST-TS-1) run in CI. |
| REQ-PROTO-3 | Define sealantd identifier newtypes `RuntimeId, ExecutionId, SessionId, ProcessId, RequestId, EventId, Sequence, StreamOffset`; the OS PID is never the stable `ProcessId` (plan §8.3, §10.2). | Must | sealant-protocol | Designed | TST-PROTO-3, TST-PROC-2 | None | PID/PGID/pidfd carried as separate metadata, not as the logical id. |
| REQ-PROTO-4 | Emit the full event envelope (`schemaVersion, eventId, runtimeId, executionId, sessionId, processId, requestId, sequence, observedAt, monotonicTimestamp, eventType, captureMethod, confidence`); serializable into the monorepo `{ eventId, sandboxId, attemptId?, type, occurredAt, message?, data }` envelope (`sandboxEventSchema`, `api-contracts/src/core-api/sandboxes.ts:194-203`; plan §8.4, brief §7.10). | Must | sealant-protocol | Designed | TST-PROTO-4, TST-TS-2 | None | `confidence`/`captureMethod` map into the `data` field; not first-class DB columns yet. |
| REQ-PROTO-5 | Negotiate `schemaVersion` on socket connect; reject unsupported versions with `unsupported-version`. No handshake exists in the monorepo today and must be designed (plan §8.1; brief §7.11). | Must | sealant-protocol | Designed | TST-PROTO-5 | None | Single version (`1`) at Phase 0; forward-compat decode is a TS-side concern (REQ-TS-4). |
| REQ-PROTO-6 | Arbitrary process/terminal bytes travel as base64 with the original byte count recorded; never assume UTF-8 (plan §4.5, §12). | Must | sealant-protocol | Designed | TST-PROTO-6, TST-IO-1 | None | Base64 inflates JSON ~33%; large payloads should go to artifacts (REQ-SPOOL-5). |

## CTRL — Unix socket control server and dispatch

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-CTRL-1 | Bind a Unix domain socket at a configurable path (default `/run/sealantd.sock`) with perms `0600` before accepting any control request; handle stale socket paths without blindly unlinking arbitrary files (plan §8.1, §18; brief §7.1, §1 insertion point). | Must | sealant-control | Designed | TST-CTRL-1, TST-SEC-2 | Writable runtime dir analogous to today's `$SSH_RUNTIME_DIR` (brief §6). | Same-namespace root workload can still reach the socket (plan §18 threat matrix). |
| REQ-CTRL-2 | Dispatch the full command set: `runtime.health/getCapabilities/gracefulShutdown/kill`, `execution.start/stop`, `exec`, `signalProcess`, `killProcess`, `listProcesses`, `writeStdin`, `closeStdin`, `openSession`, `closeSession`, `resizePty`, `listSessions`, `setFeatureState`, `getRuntimeMetrics` (plan §8.5). | Must | sealant-control | Designed | TST-CTRL-2 | None | Commands map to the gateway call sites in brief §3. |
| REQ-CTRL-3 | Every request gets exactly one ack or one typed control error keyed by `requestId`; long work surfaces as later telemetry, never a hanging response; `requestId` enables duplicate-request handling (plan §8.6). | Must | sealant-control | Designed | TST-CTRL-3 | None | Idempotency window is bounded by in-memory request tracking. |
| REQ-CTRL-4 | Expose the closed error-code union (`invalid-json, unsupported-version, frame-too-large, unknown-command, invalid-argument, missing-command, execution-not-found, session-not-found, process-not-found, process-start-failed, pty-allocation-failed, permission-denied, policy-denied, feature-unavailable, capability-unavailable, queue-full, runtime-shutting-down, internal-error`) deserializable by the TS client (plan §8.5 error codes; brief §7.12). | Must | sealant-control | Designed | TST-CTRL-4, TST-TS-3 | None | New codes are an additive, version-gated change (REQ-PROTO-5). |
| REQ-CTRL-5 | Provide an optional stdio adapter for wrappers/deterministic tests: protocol bytes to stdout, human diagnostics to stderr only (plan §8.1). | Should | sealant-control | Designed | TST-CTRL-5 | None | Stdio mode is single-peer; multiplexing is socket-only. |
| REQ-CTRL-6 | Validate Linux peer credentials (`SO_PEERCRED`) on socket accept where appropriate (plan §8.1, §18). | Should | sealant-control | Designed | TST-CTRL-6, TST-SEC-2 | `SO_PEERCRED` (Linux only; not validated on macOS host). | Auth of end users stays with the ssh-gateway; sealantd trusts the already-authenticated caller (brief §3). |

## CFG — Runtime configuration and validation

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-CFG-1 | Accept validated config from file, environment, or boot payload; bind `sandboxId` at config level and carry `RuntimeId` per daemon instance (one per sandbox+run) (plan §9; brief §2 canonical ids). | Must | sealant-runtime-core | Designed | TST-CFG-1 | None | `sandboxId`/`runId`(=attemptId) are opaque `text` from `control-plane.ts`; format not minted here. |
| REQ-CFG-2 | Validate config before reporting healthy; emit a sanitized config summary and a deterministic config hash (plan §9, §17). | Must | sealant-runtime-core | Designed | TST-CFG-2, TST-HEALTH-1 | None | Hash covers only declared fields; undeclared env is ignored. |
| REQ-CFG-3 | Carry every configured bound: max frame size, I/O chunk size, queue capacities, per-execution buffered bytes, max processes/sessions, spool disk limit + segment size, max diff/artifact size, watch roots, shutdown grace, retry age (plan §4.3, §9). | Must | sealant-runtime-core | Designed | TST-CFG-3, TST-SPOOL-6 | None | Defaults must be safe for the smallest sandbox; no autotuning. |
| REQ-CFG-4 | Build an explicit child base environment; never blindly pass `std::env::vars()`; strip telemetry creds, control tokens, internal endpoints, spool keys, debug secrets; validate env keys; emit only allowlisted/redacted env metadata (plan §9, §18 isolation). | Must | sealant-runtime-core | Designed | TST-CFG-4, TST-SEC-5 | None | Cannot retroactively scrub secrets already in a parent process image. |
| REQ-CFG-5 | Validate `ExecutionId` carries the monorepo `runId`(==attemptId) and refuse to start healthy if the run correlation key is missing (plan §9; brief §2, §7.7). | Must | sealant-runtime-core | Designed | TST-CFG-5 | None | 1:1 with `sandbox_runtime_instances.run_id` (`sandbox-build-jobs.ts:64-91`). |

## PROC — Process execution and lifecycle

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-PROC-1 | `exec` supports argv (no bare shell string), working dir, validated env overlay, optional stdin, separate stdout/stderr, foreground/background, timeout/cancellation, execution/session association, optional resource sampling, graceful-then-forced termination (plan §10.1). | Must | sealant-process | Designed | TST-PROC-1, TST-IO-2 | None | Shell execution must be explicit (`/bin/bash -lc …`); no implicit shell parsing. |
| REQ-PROC-2 | Maintain a managed process record: logical `ProcessId`, OS PID, PGID, pidfd where available, parent logical process, command/cwd/sanitized metadata, stream offsets, exit code/signal/reason/duration/timestamps; enforce the `created→starting→running→terminating→exited|signaled|failed` state machine and reject invalid transitions (plan §10.2, §10.3). | Must | sealant-process | Designed | TST-PROC-2 | None | Parent attribution only where observable; not guaranteed for double-forks. |
| REQ-PROC-3 | Create deliberate process groups so signals target the managed tree; translate SSH signal names (`gateway-server.ts:231`) to OS signals and deliver to the process group (plan §10.4; brief §3, §7.4). | Must | sealant-process | Designed | TST-PROC-3, TST-PTY-5 | None | Signal name set limited to what SSH forwards. |
| REQ-PROC-4 | Use pidfds to avoid PID-reuse races with a documented fallback; investigate `PR_SET_CHILD_SUBREAPER` to adopt/reap orphaned descendants; if running as PID 1, implement PID-1 reaping; set close-on-exec on daemon-only descriptors (plan §10.4). | Must | sealant-process | Designed | TST-PROC-4 | Linux ≥5.3 for `pidfd_open`/`CLONE_PIDFD`; subreaper is Linux ≥3.4. | macOS host lacks pidfd/subreaper — validated only in Linux containers (brief §6). |
| REQ-PROC-5 | Capture and return the real exit code for exec so the gateway's `incomingChannel.exit(code)` path (`gateway-server.ts:318-322`) reports it accurately (plan §10.1; brief §7.6). | Must | sealant-process | Designed | TST-PROC-5 | None | Signal-terminated processes report signal, not a clean exit code. |
| REQ-PROC-6 | Run the shutdown sequence: stop new work → mark terminating → graceful signal to group → wait grace → SIGKILL → reap direct+adopted descendants → drain streams → emit final lifecycle + telemetry-loss events; leave no zombies/orphans (plan §10.5, §22 Phase 2 gate). | Must | sealant-process | Designed | TST-PROC-6, TST-PROC-3 | `PR_SET_CHILD_SUBREAPER` for adopted descendants. | Without subreaper, escaped grandchildren may be reaped by init, not sealantd. |

## PTY — Pseudoterminal and interactive sessions

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-PTY-1 | Allocate a PTY master/slave pair per session, create a session + controlling terminal, set the foreground process group, and start the configured shell/command; release all resources after normal or abnormal exit (plan §11, §22 Phase 3 gate). | Must | sealant-pty | Designed | TST-PTY-1, TST-PTY-7 | `openpty`/`TIOCSCTTY` via `nix`/`rustix`; works unprivileged (brief §6). | macOS PTY semantics differ — Linux-only behavior validated in containers. |
| REQ-PTY-2 | Apply client-supplied `{cols, rows, width, height, modes}` exactly as forwarded from the stored `sessionPty` (`gateway-server.ts:248-257`) on `openSession` (shell ← `upstream.shell`, line 259) (plan §11; brief §3, §7.2). | Must | sealant-pty | Designed | TST-PTY-2 | None | Terminal modes limited to what the SSH layer transmits. |
| REQ-PTY-3 | Handle resize by mapping `setWindow(rows, cols, height, width)` (`gateway-server.ts:225`) to `TIOCSWINSZ` on the session PTY (plan §11; brief §7.3). | Must | sealant-pty | Designed | TST-PTY-3 | `TIOCSWINSZ` ioctl. | None. |
| REQ-PTY-4 | Capture PTY input and output as raw bytes with preserved chunk boundaries; the daemon forwards bytes and is not a terminal emulator (plan §11, §12). | Must | sealant-pty | Designed | TST-PTY-4, TST-IO-1 | None | No causal ordering guarantee across input/output relative to other streams (plan §4.6). |
| REQ-PTY-5 | Service `openSession` (exec, optional PTY ← `upstream.exec`, `gateway-server.ts:296`) and model terminal-generated signals (Ctrl+C → SIGINT to foreground group) accurately (plan §11; brief §3). | Must | sealant-pty | Designed | TST-PTY-5, TST-PROC-3 | None | Subsystem (SFTP) and tcpip forwarding (brief §3) coexist but are out of PTY scope. |
| REQ-PTY-6 | On `closeSession` / proxy disconnect (`gateway-server.ts:418-428`), tear down the PTY, terminate the session process group, and record the final process/session result (plan §11, §22 Phase 3 gate). | Must | sealant-pty | Designed | TST-PTY-6, TST-PTY-7 | None | Abrupt proxy loss may truncate trailing output; truncation is reported (REQ-PIPE-5). |

## IO — Stream capture and chunk metadata

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-IO-1 | Transport stdin/stdout/stderr and pty.input/pty.output as binary-safe byte streams: no UTF-8 transform, no line buffering, preserved chunk-boundary metadata; NUL bytes and invalid UTF-8 round-trip (plan §12; brief §7.5; §22 Phase 1 gate). | Must | sealant-telemetry | Designed | TST-IO-1, TST-PROTO-6 | None | Separate stdout/stderr pipes give no perfect cross-stream causal order (plan §4.6). |
| REQ-IO-2 | Emit per-chunk metadata: stream kind, encoding, original byte count, monotonic per-stream `streamOffset`, capture time, inline-or-artifact content, transformation metadata, correlation ids (plan §12 chunk table, §8.4). | Must | sealant-telemetry | Designed | TST-IO-2, TST-PROTO-4 | None | `streamOffset` is per-stream only; no global byte clock. |
| REQ-IO-3 | Run the capture data path: child pipe/PTY → bounded capture queue → validation+redaction → deterministic sequencing → spool/event-writer → sink (plan §12 data path). | Must | sealant-telemetry | Designed | TST-IO-3, TST-PIPE-1 | None | Path latency depends on sink speed; producers must not block on sink (REQ-PIPE-2). |
| REQ-IO-4 | Support capture modes: full, metadata-only, disabled, pattern redaction, env-key redaction, path redaction, sensitive-input suppression; preserve byte counts/offsets when content is transformed so redacted offsets stay unambiguous (plan §12 modes). | Should | sealant-telemetry | Designed | TST-IO-4, TST-SEC-7 | None | Redaction is pattern-based, best-effort; novel secret shapes may pass through. |
| REQ-IO-5 | Make queue-full behavior policy-driven and observable: block producers, spill to disk, drop eligible low-priority events, terminate the execution, or mark runtime degraded (plan §12, §15). | Must | sealant-telemetry | Designed | TST-IO-5, TST-PIPE-3 | None | Each policy trades latency vs. completeness; choice is per-config (REQ-CFG-3). |

## FS — Filesystem telemetry

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-FS-1 | Run the hybrid strategy: baseline snapshot → live watcher → final snapshot + diff → overflow/uncertainty rescan; emit `file.added/modified/deleted/renamed/metadataChanged/watchOverflow/snapshotCompleted/diffAvailable` (plan §13). | Must | sealant-fs | Designed | TST-FS-1 | inotify (Linux). | inotify is in-process instrumentation; no eBPF (privilege not conveyed, brief §6). |
| REQ-FS-2 | Restrict observation to configured workspace roots; protect against symlink loops and path escape; handle special and very large files safely (plan §13 protections, §22 Phase 5 gate). | Must | sealant-fs | Designed | TST-FS-2 | None | Workspace scope tied to the run's checked-out repo (plan §2 context). |
| REQ-FS-3 | Coalesce editor temp-file patterns and repetitive metadata noise; apply ignore rules to generated trees (e.g. `node_modules`); add watches for new dirs and handle deleted directory trees (plan §13). | Should | sealant-fs | Designed | TST-FS-3 | inotify watch descriptors (bounded). | Watch-descriptor exhaustion forces overflow → rescan (REQ-FS-4). |
| REQ-FS-4 | Emit an explicit `file.watchOverflow` and trigger a rescan whenever the watcher cannot guarantee completeness (plan §13, §22 Phase 5 gate). | Must | sealant-fs | Designed | TST-FS-4 | inotify queue limits. | Rescan is point-in-time; events between overflow and rescan are inferred, not observed. |
| REQ-FS-5 | Generate text patches only under configured type/size limits; store large/binary patches as content-addressed artifacts; state whether rename detection is certain or inferred; do not claim reliable per-process attribution from inotify alone (plan §13 diffs, §4.6). | Should | sealant-fs | Designed | TST-FS-5, TST-SPOOL-5 | None | Per-process FS attribution is not reliable without privileged backends. |

## NET — Network telemetry and source attribution

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-NET-1 | Implement capability-aware modes `off / metadata / proxy / privileged / payload`; detect kernel features and Linux capabilities at startup; expose disabled capabilities honestly (plan §14.1, §14.4). | Must | sealant-network | Designed | TST-NET-1, TST-HEALTH-2 | Varies by mode (see rows below). | `payload` mode requires separate privacy/security review; off by default. |
| REQ-NET-2 | Metadata mode: best-effort DNS observations, local/remote addrs+ports, protocol/direction, open/close timestamps, byte counts and process/session attribution where observable — without elevated privilege (plan §14.2). | Should | sealant-network | Designed | TST-NET-2 | Unprivileged; in-process instrumentation (brief §6). | Attribution best-effort; DNS visibility depends on resolver path. |
| REQ-NET-3 | Proxy mode: explicit local egress proxy recording scheme/host/port, HTTP method+path when observable, status+byte counts when observable; for HTTPS CONNECT record destination host:port without claiming encrypted paths/bodies are known (plan §14.3, §4.6). | Should | sealant-network | Designed | TST-NET-3 | Local egress proxy; workload must route through it. | Proxy bypass possible in the current namespace/privilege mode (plan §18 threat matrix). |
| REQ-NET-4 | Privileged mode: investigate eBPF / cgroup socket hooks / netlink-conntrack / packet capture / transparent proxy in a separate narrow-IPC collector; degrade cleanly when it cannot attach; never make the whole daemon permanently privileged for an optional collector (plan §14.4, §5 rules). | Later | sealant-network | Designed | TST-NET-4 | `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_NET_RAW`; not conveyed by the blueprint→adapter path today (brief §6). | Blocked by capability delivery; favor in-process instrumentation until then. |
| REQ-NET-5 | Emit normalized `network.sourceObserved` evidence (hostname, resolved IPs, port, scheme when known; URL/path only when observable; first/last seen; process/session ids; observation method + confidence; evidence event ids). sealantd emits evidence; the TS SDK decides if it is an LLM source (plan §14.5). | Should | sealant-network | Designed | TST-NET-5 | Mode-dependent. | Multiple IPs per host and unknown hostnames represented with explicit confidence. |

## PIPE — Telemetry pipeline, sequencing, backpressure

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-PIPE-1 | Implement the typed bounded pipeline stages: production → validation → redaction/policy → sequence assignment → batching → durable spool → delivery → ack → retry/acked-deletion (plan §15). | Must | sealant-telemetry | Designed | TST-PIPE-1, TST-SPOOL-4 | None | Stages share bounded memory; total footprint is config-capped (REQ-CFG-3). |
| REQ-PIPE-2 | Capture producers never synchronously depend on a slow remote sink; bounded memory queues with explicit backpressure; exponential backoff with jitter; sink disconnect/reconnect handling (plan §5 rules, §15, §22 Phase 4 gate). | Must | sealant-telemetry | Designed | TST-PIPE-2 | None | A persistently dead sink eventually forces spill or drop (REQ-IO-5). |
| REQ-PIPE-3 | Assign final `sequence` values at exactly **one** deterministic point per runtime (not per producer task); I/O events also carry monotonic per-stream `streamOffset` (plan §5 rules, §8.4, §15). | Must | sealant-telemetry | Designed | TST-PIPE-3, TST-IO-2 | None | Sequence reflects Sealant-observed/enqueue order, not kernel causality (plan §8.4). |
| REQ-PIPE-4 | Enforce priority classes — Critical (control errors, runtime state changes, process start/exit, session close, drop/corruption events) spool before delivery and are never silently discarded; Normal buffered/spilled; Low coalesced/dropped with counters (plan §15 priority table, §4.4). | Must | sealant-telemetry | Designed | TST-PIPE-4, TST-PIPE-5 | None | Under extreme load only Critical preservation is guaranteed. |
| REQ-PIPE-5 | No telemetry loss is silent: when data is dropped/truncated/redacted/coalesced/unavailable, emit a normalized event or counter; provide idempotent delivery keys and duplicate-safe resend (plan §4.4, §15). | Must | sealant-telemetry | Designed | TST-PIPE-5, TST-SPOOL-4 | None | Counters quantify loss but cannot reconstruct dropped bytes. |

## SPOOL — Durable spool and artifacts

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-SPOOL-1 | Append-only record format: magic/format version, record length, event id, execution sequence, timestamp, typed payload, checksum; append+flush with configurable fsync policy (plan §16). | Must | sealant-eventlog | Designed | TST-SPOOL-1 | Writable spool dir on a real filesystem. | fsync policy trades durability vs. throughput; configured per REQ-CFG-3. |
| REQ-SPOOL-2 | Replay unacknowledged records after restart and recover from a partial final record; deterministic handling of truncated final record and crash-between-write-and-fsync (plan §16, §22 Phase 4 gate). | Must | sealant-eventlog | Designed | TST-SPOOL-2 | None | At-least-once delivery → consumers must dedupe on `eventId` (REQ-PIPE-5). |
| REQ-SPOOL-3 | Detect corruption via checksums and emit a corruption event; deterministic on corrupt checksum, sequence gap, and oversized record (plan §16, §22 Phase 4 gate). | Must | sealant-eventlog | Designed | TST-SPOOL-3 | None | Corrupt records are reported and skipped, not repaired. |
| REQ-SPOOL-4 | Enforce disk limit, rotate segments, delete acknowledged segments, and explicitly report unrecoverable loss; handle rotation during active writes (plan §16). | Must | sealant-eventlog | Designed | TST-SPOOL-4, TST-SPOOL-6 | None | Disk-full/permission failure degrades to drop-with-counter (REQ-IO-5). |
| REQ-SPOOL-5 | Store large output, patches, packet captures, and other blobs as content-addressed artifacts referenced by telemetry events (plan §5 rules, §16). | Should | sealant-eventlog | Designed | TST-SPOOL-5, TST-FS-5 | None | Artifact store shares the spool disk limit; thresholds per REQ-CFG-3. |
| REQ-SPOOL-6 | Honor spool disk limit and segment size; fail-injection covers disk full, permission failure, duplicate replay, and oversized record (plan §16 mandatory failure tests, §4.3). | Must | sealant-eventlog | Designed | TST-SPOOL-6, TST-SPOOL-3 | Writable spool dir. | Bound is bytes-on-disk; in-flight memory bound is separate (REQ-CFG-3). |

## HEALTH — Health, capabilities, metrics, kill switches

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-HEALTH-1 | Model runtime states `starting/healthy/degraded/unhealthy/shuttingDown/stopped`; emit heartbeats only after startup validation completes (plan §17). | Must | sealant-runtime-core | Designed | TST-HEALTH-1, TST-CFG-2 | None | Health reflects sealantd-observable subsystems only. |
| REQ-HEALTH-2 | `runtime.health` reports queue depth/capacity, spool usage/limit, retry count + last successful delivery, dropped/redacted/coalesced/truncated counters, active executions/sessions/processes, FS watcher+snapshot status, network backend+capability state, sink connectivity, kill-switch states, and concrete degradation reasons (plan §17). | Must | sealant-runtime-core | Designed | TST-HEALTH-2, TST-NET-1 | None | Counters are best-effort under extreme load. |
| REQ-HEALTH-3 | Map sealantd lifecycle to `sandbox_runtime_instances` transitions `pending→running→failed|stopped` including `endpoint`, `resource_id`, `reference`, `error_code`/`error_message` (`sandbox-build-jobs.ts:64-91`; brief §4, §7.9). | Must | sealant-runtime-core | Designed | TST-HEALTH-3, TST-TS-2 | None | Daemon reports facts; the worker writes the DB row, not sealantd directly (brief §4). |
| REQ-HEALTH-4 | Implement `setFeatureState` kill switches for FS diffing, live FS watching, network collection, payload capture, verbose I/O capture, and resource sampling (plan §17, §8.5). | Must | sealant-runtime-core | Designed | TST-HEALTH-4 | None | Toggling mid-run leaves a gap that is reported as a degradation event (REQ-PIPE-5). |

## SEC — Security, isolation, threat model

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-SEC-1 | Run the daemon under a protected identity and child workloads under a separate unprivileged UID where practical; minimize Linux capabilities and drop privilege after init; set close-on-exec on daemon-only descriptors (plan §18 goals). | Should | sealant-runtime-core | Designed | TST-SEC-1 | UID separation needs a second UID in-image; `CAP_SETUID`/`CAP_SETGID` to switch. | Plain `docker run` containers (brief §6) may not provide a second UID; degrades to same-UID. |
| REQ-SEC-2 | Restrict socket mode/ownership and validate peer credentials; reject unauthorized control clients (plan §18 threat matrix, §22 Phase 7 gate). | Must | sealant-control | Designed | TST-SEC-2, TST-CTRL-6 | `SO_PEERCRED` (Linux). | Same-namespace root workload can bypass file-mode checks (plan §18). |
| REQ-SEC-3 | Protect against fork bombs, output floods, event storms, and oversized protocol frames; enforce max frame before allocation and per-resource limits (plan §18, §4.3; brief §7.1). | Must | sealant-runtime-core | Designed | TST-SEC-3, TST-PROTO-1 | None | Limits cap blast radius; a determined root workload can still exhaust the namespace. |
| REQ-SEC-4 | Prevent fake telemetry injection and spool tampering: workloads must not write directly to the spool or event transport; protect ownership, checksums, permissions; emit corruption events (plan §18 threat matrix). | Must | sealant-eventlog | Designed | TST-SEC-4, TST-SPOOL-3 | Spool dir owned by daemon UID, not child UID. | Without UID separation (REQ-SEC-1) a same-UID child could touch spool files. |
| REQ-SEC-5 | Isolate secrets: exclude runtime secrets from child env and inherited descriptors; never duplicate secrets into `tracing` diagnostics; redact secret-like output; consider `PR_SET_DUMPABLE`/ptrace restrictions (plan §18 isolation + logging, §22 Phase 7 gate). | Must | sealant-runtime-core | Designed | TST-SEC-5, TST-SEC-7 | `PR_SET_DUMPABLE`, Yama ptrace_scope (Linux). | ptrace/eBPF observation needs capabilities not conveyed today (brief §6). |
| REQ-SEC-6 | Use structured `tracing` diagnostics to stderr / a dedicated sink, kept strictly separate from the typed product telemetry pipeline (plan §18 logging vs telemetry). | Must | sealant-runtime-core | Designed | TST-SEC-6 | None | Diagnostics are not durable evidence; only pipeline events are spooled. |

## TS — TypeScript contracts and SDK

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-TS-1 | Generate `@sealant/runtime-protocol` TS types from the Rust schema (serde + schemars JSON Schema → TS); contract tests prove Rust↔TS agreement on protocol version 1; mirror `api-contracts` Effect Schema conventions (`Schema.Literal` enums, `Schema.optional`, camelCase structs) (plan §8.2, §19; brief §5; §22 Phase 0 gate). | Must | packages/runtime-protocol | Designed | TST-TS-1, TST-PROTO-2 | None | Lower runtime libs use zod v4; the wire-facing protocol standardizes on Effect Schema (brief §5). |
| REQ-TS-2 | Model errors as `Schema.TaggedError` classes with a closed code set mirroring the 8 `Sandbox*Error` classes (`api-contracts/src/core-api/sandboxes.ts:215-293`); mint stable session/process/event ids as non-empty strings compatible with `sandboxEventSchema.eventId` (`sandboxes.ts:195`) (plan §8.5, §19; brief §7.8, §7.12). | Must | packages/runtime-protocol | Designed | TST-TS-2, TST-CTRL-4 | None | No `sbx_`/`run_` prefix convention exists in schema; ids are bare non-empty strings (brief §2). |
| REQ-TS-3 | `@sealant/runtime-client` exposes `health(), getCapabilities(), startExecution(), exec(), openSession(), writeStdin(), resizePty(), signalProcess(), closeSession(), shutdown(), events(): AsyncIterable<TelemetryEvent>` over IPC (no Rust↔Node FFI); provide binary payload helpers (plan §19). | Must | packages/runtime-client | Designed | TST-TS-3 | None | IPC is the language boundary; FFI is an explicit non-goal (plan §19). |
| REQ-TS-4 | Define reconnection and duplicate-request behavior and support forward-compatible event decoding; generate Rust fixtures consumed by TS and TS fixtures consumed by Rust; run end-to-end tests through the real daemon (plan §19; §22 Phase 1 gate). | Must | packages/runtime-client | Designed | TST-TS-4 | None | Forward-compat decode tolerates unknown event types but cannot interpret them. |
| REQ-TS-5 | Package both as `@sealant/runtime-protocol` / `@sealant/runtime-client` with `"version":"0.0.0"`, `"private":true`, `"type":"module"`, source `exports` (no build step), `effect`/`@effect/platform` via `catalog:`, internal deps via `workspace:*`; scripts `oxlint .` + `tsgo -p tsconfig.json --noEmit`; tests in vitest (brief §5, §7.13). | Must | packages/runtime-protocol | Designed | TST-TS-5 | None | Catalog pins (effect ^3.21, @effect/platform ^0.96) live in `pnpm-workspace.yaml`. |

## PKG — Packaging, binary, and BuildKit integration

| ID | Requirement | Priority | Owning crate | Status | Test IDs | Capability/Privilege | Known limitations |
|----|-------------|----------|--------------|--------|----------|----------------------|-------------------|
| REQ-PKG-1 | Ship a single statically-linked musl `linux/amd64` `sealantd` binary that runs unprivileged on Fedora-41, Arch, and `nixos/nix` base images with no dependency on distro-specific shared libs (`buildkit-builder.ts` distroDefinitions; brief §6, §7.14; plan §20). | Must | sealantd | Designed | TST-PKG-1 | Unprivileged; PTY works without caps (brief §6). | macOS host builds cross-platform; Linux artifact validated only in containers. arm64 not in the matrix yet (brief §6). |
| REQ-PKG-2 | Extend `renderContainerfile` to stage `sealantd` and add `COPY sealantd /usr/local/bin/sealantd` + `RUN chmod 755` after line 1060; start sealantd in `renderSandboxEntrypoint` before the sshd block (~line 838) and before the harness foreground command (line 842) so it owns PTY/process lifecycle (brief §1, §6, §7.15; plan §20). | Must | sealantd | Designed | TST-PKG-2 | None | Touches `sealant-core` build code (`buildkit-builder.ts`); requires monorepo-side change. |
| REQ-PKG-3 | The sandbox MUST fail closed (refuse the session) if the sealantd socket is unreachable at session-open time (brief §7.15; plan §4.4). | Must | sealantd | Designed | TST-PKG-3, TST-CTRL-1 | None | Fail-closed is at the gateway/entrypoint seam; enforcement lives partly in `sealant-core`. |
| REQ-PKG-4 | Provide `sealantctl` debug/integration client and binary metadata flags `--version`, `--check-config`, `--print-capabilities` (plan §20; brief §7 implied by capability reporting). | Should | sealantctl | Designed | TST-PKG-4 | None | `--print-capabilities` output is environment-dependent (REQ-NET-1, REQ-PROC-4). |
| REQ-PKG-5 | Own a writable runtime dir for the socket analogous to today's `$SSH_RUNTIME_DIR`; emit build metadata and ship debug symbols (or a separate symbol artifact) without breaking the static-binary or PTY behavior (plan §20; brief §6). | Should | sealantd | Designed | TST-PKG-5, TST-CTRL-1 | Writable runtime dir in-container. | Nix image is non-FHS (no `/usr/sbin`); runtime dir must not assume FHS layout (brief §6). |
