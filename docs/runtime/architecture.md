# sealantd Architecture

`sealantd` is the authoritative runtime daemon that runs inside a Sealant Linux sandbox and records a factual evidence trail over a versioned, length-prefixed JSON Unix-socket protocol consumed by a TypeScript SDK. It emits facts; the SDK performs higher-level interpretation (plan §5). This document grounds the target architecture, crate boundaries, the telemetry data path, the sandbox insertion model, the correlation/identity model, and per-subsystem failure policy.

Sources: `docs/runtime/integration-brief.md` (monorepo seams, real file paths) and `plan.html` (sections cited as "plan §N").

---

## 1. Target architecture (plan §5)

```
TypeScript orchestrator / SDK / modules   (@sealant/runtime-client)
                │
                │ versioned, length-prefixed JSON frames
                │ (4-byte big-endian length + JSON body)
                ▼
      Unix socket /run/sealantd.sock (0600)  [optional stdio adapter]
                │
                ▼
┌──────────────────────────────────────────────────────────┐
│                       sealantd                            │
│                                                          │
│  Control server ──► command dispatcher ──► state machines│
│         │                       │                         │
│         │             ┌─────────┴─────────┐               │
│         │             ▼                   ▼               │
│         │       process runtime       PTY sessions        │
│         │             │                   │               │
│         ├─────────────┴───────────────┬───┤               │
│         ▼                             ▼   ▼               │
│  filesystem collector        network collectors          │
│         │                             │                   │
│         └──────────────┬──────────────┘                   │
│                        ▼                                  │
│       validation → redaction → sequencing → batching      │
│                        │                                  │
│                        ▼                                  │
│       bounded queues → durable spool → delivery sink      │
│                        │                                  │
│                        ▼                                  │
│                health / metrics / drops                   │
└──────────────────────────────────────────────────────────┘
```

Architectural invariants carried into the design (plan §5):

- The daemon emits facts; the SDK interprets. No semantic LLM reasoning lives in `sealantd`.
- Protocol and telemetry types are versioned and shared, never manually duplicated: Rust `serde` structs are the single schema source, `schemars` emits JSON Schema, which generates the TS types.
- Final event sequencing occurs at **one deterministic point per runtime** (see §5 below; plan §5, §15).
- Capture producers never synchronously depend on a slow remote sink — they hand off to bounded queues backed by the durable spool.
- Optional privileged collectors must not force the whole daemon to run permanently as root. The brief constrains us further: eBPF/ptrace need capabilities the blueprint→adapter path does not convey today (`integration-brief.md` §6), so the default network/fs collection is in-process, unprivileged instrumentation.
- Large data is stored as content-addressed artifacts and referenced by id, not inlined.

---

## 2. Crate boundaries (11 crates + 2 binaries)

Workspace shape per plan §7. The dependency direction is strictly downward in this table: a crate may depend only on crates listed **below** it in the "may depend on" column. **There are no cycles.** `sealant-protocol` is the root: it depends on **nothing internal** — only on `serde`, `serde_json`, `schemars` — so it is usable by the daemon, by `sealantctl`, by tests, and by the TS-type generation step without dragging in Tokio or OS code.

| Crate | Responsibility | Key external deps | May depend on (internal) |
|---|---|---|---|
| `sealant-protocol` | Typed commands, events, error-code union, the event envelope, and all id newtypes (`RuntimeId`, `ExecutionId`, `SessionId`, `ProcessId`, `RequestId`, `EventId`, `Sequence`, `StreamOffset`). Single schema source for TS generation. | `serde`, `serde_json`, `schemars`, `thiserror` | **none** |
| `sealant-runtime-core` | Validated configuration, runtime/process/session state machines, fail-open vs fail-closed policy, health/capability model, feature kill switches, config hash. Domain logic kept independent of Tokio where practical (plan §4.1). | `serde`, `thiserror`, `tracing` | `sealant-protocol` |
| `sealant-eventlog` | Append-only durable spool: magic/format-version, record length, eventId, sequence, timestamp, typed payload, checksum; replay, partial-record recovery, rotation, disk-limit enforcement, acknowledged-segment deletion (plan §16). | `serde_json`, `crc`/checksum, `tracing` | `sealant-protocol`, `sealant-runtime-core` |
| `sealant-telemetry` | Event bus, the produce→validate→redact→sequence→batch pipeline, the single deterministic sequencing point, priority classes, backpressure policy, delivery sink, retry/backoff, drop counters (plan §15). | `tokio`, `serde_json`, `tracing` | `sealant-protocol`, `sealant-runtime-core`, `sealant-eventlog` |
| `sealant-process` | Non-PTY `exec`, process registry, process groups, pidfd/subreaper handling, reaping, stdout/stderr capture, exit-code surfacing. The OS PID is never the stable `ProcessId`. | `tokio`, `nix`/`rustix`, `libc` | `sealant-protocol`, `sealant-runtime-core`, `sealant-telemetry` |
| `sealant-pty` | PTY master/slave allocation, controlling terminal, foreground process groups, raw byte I/O, resize (`TIOCSWINSZ`), terminal signal modeling. PTY works unprivileged (`integration-brief.md` §6). | `tokio`, `nix`/`rustix`, `libc` | `sealant-protocol`, `sealant-runtime-core`, `sealant-telemetry` |
| `sealant-fs` | Baseline snapshot, inotify live observation, final snapshot/diff, overflow→rescan recovery, coalescing, content-addressed diff artifacts. No reliable per-process attribution claimed from inotify alone (plan §13). | `tokio`, `notify`/`inotify`, hashing | `sealant-protocol`, `sealant-runtime-core`, `sealant-telemetry` |
| `sealant-network` | Capability-aware collectors (`off`/`metadata`/`proxy`/`privileged`/`payload`), DNS/connection metadata, egress proxy evidence, source normalization. Defaults to in-process metadata/proxy; privileged backends degrade cleanly when capabilities are absent (plan §14, `integration-brief.md` §6). | `tokio`, `serde`, optional netlink/eBPF | `sealant-protocol`, `sealant-runtime-core`, `sealant-telemetry` |
| `sealant-control` | Unix-socket listener, optional stdio adapter, length-prefixed JSON framing (4-byte BE length + body, max-frame enforced before allocation), socket-permission/peer-credential checks, request dispatch, one-ack-per-request contract (plan §8). | `tokio`, `tokio-util` (codec), `serde_json` | `sealant-protocol`, `sealant-runtime-core`, `sealant-telemetry`, `sealant-process`, `sealant-pty` |
| `sealantd` (bin) | Binary composition and lifecycle: config load/validate, socket bind, collector wiring, graceful drain/shutdown, `--check-config`, `--print-capabilities`. | `tokio`, `clap`, `tracing` | all `sealant-*` crates |
| `sealantctl` (bin) | Debug + integration-test client speaking the same protocol; used for failure-injection and contract tests. | `tokio`, `clap`, `serde_json` | `sealant-protocol`, `sealant-control` |

Cross-cutting rule (plan §5, §7): every emitting crate (`sealant-process`, `sealant-pty`, `sealant-fs`, `sealant-network`) depends on `sealant-telemetry` to publish events but **never** on each other, and none depend on `sealant-control`. Control flows down through `sealant-control`; evidence flows down through `sealant-telemetry`; both terminate at `sealant-eventlog`. This keeps the graph acyclic.

---

## 3. End-to-end telemetry data path (plan §12 + §15)

A single typed, bounded, observable pipeline serves every producer (I/O chunks, fs mutations, network connections, lifecycle events). Stages:

```
produce ─► validate ─► redact/policy ─► sequence ─► batch ─► spool ─► deliver ─► ack
   │                                       │                   │                  │
(child pipe/PTY,                  ONE deterministic     append+checksum    retry/backoff
 inotify, conn)                   sequencing point      fsync policy       or acked delete
```

1. **Produce** — `sealant-process`/`sealant-pty` capture stdin/stdout/stderr and `pty.input`/`pty.output` as raw bytes; `sealant-fs`/`sealant-network` emit normalized events. Producers push into a **bounded** capture queue and never block on the remote sink (plan §12 data path). Arbitrary bytes are never assumed UTF-8 — JSON frames carry base64 plus the original byte count (plan §4.5).
2. **Validate** — frames/events validated against the schema before further work.
3. **Redact / policy** — pattern, env-key, and path redaction; sensitive-input suppression. Original byte counts and `streamOffset` values are preserved when content is transformed so redacted offsets stay unambiguous (plan §12).
4. **Sequence** — final `Sequence` values are assigned at **one deterministic point per runtime** in `sealant-telemetry`, not independently in producer tasks (plan §5, §15). I/O events additionally carry a monotonic per-stream `StreamOffset`.
5. **Batch** — by size and time thresholds, with event priority classes (Critical / Normal / Low, plan §15). Critical events (control errors, runtime state changes, process start/exit, session close, drop/corruption events) are spooled before delivery and never silently discarded.
6. **Spool** — `sealant-eventlog` appends each record (magic/version, length, eventId, sequence, timestamp, typed payload, checksum) with a configurable fsync policy; survives crash, recovers from a partial final record (plan §16).
7. **Deliver** — to the configured sink with exponential backoff + jitter and disconnect/reconnect handling. Delivery is at-least-once and duplicate-safe via `EventId` idempotency keys.
8. **Ack** — acknowledged segments are deleted from the spool; unacked events are replayed after restart. Unrecoverable loss is reported explicitly via a normalized event/counter — no telemetry loss is silent (plan §4.4, §15).

Queue-full behavior is policy-driven and observable: block producers, spill to disk, drop eligible low-priority events with counters, terminate the execution, or mark the runtime degraded (plan §12).

---

## 4. Sandbox insertion model (`integration-brief.md` §1, §6)

Today command execution is fully delegated to an in-container `sshd` launched with `ForceCommand /usr/local/bin/sandbox-ssh-shell`; the ssh-gateway pipes channels to it (`apps/ssh-gateway/src/gateway-server.ts`). No per-process / PTY / I/O / fs / network capture exists anywhere. `sealantd` takes over PTY/process ownership at two precise seams in the BuildKit renderer.

**Seam 1 — binary copy (`packages/sandboxes/src/buildkit/buildkit-builder.ts`, `renderContainerfile`).** Immediately after the existing `COPY entrypoint.sh /usr/local/bin/sandbox-entrypoint` at **line 1060**, add `COPY sealantd /usr/local/bin/sealantd` plus `RUN chmod 755`. The binary is staged into the build context alongside `entrypoint.sh` (written by `writeBuildContext`, ~lines 1079–1098).

**Seam 2 — daemon launch (`renderSandboxEntrypoint`, same file).** Launch `sealantd` in the entrypoint **before the sshd block (line 838)** and **before the foreground harness command (line 842, `printf "$HARNESS_BANNER"`)**, so the daemon owns the PTY/process lifecycle and the gateway's upstream shell/exec lands on a `sealantd`-spawned process rather than a bare login shell.

**Control entry point.** `sealantd` binds a Unix domain socket at `/run/sealantd.sock` with permissions `0600` before accepting any control request. The ssh-gateway (which still owns SSH auth, `integration-brief.md` §3) maps its session calls onto the protocol: `session.on("shell")`→`openSession`, `session.on("exec")`→`openSession`(exec), `pipeStreams`→`writeStdin`/stdout-stderr (binary-safe), `window-change`→`resizePty`, `signal`→signal translation, connection `close`→`closeSession`. The sandbox **fails closed** at session-open time if the socket is unreachable (plan §4.4; brief requirement 15).

**Single artifact.** Ship one statically-linked **musl linux/amd64** binary so it is safe across the three base images (Fedora glibc, Arch glibc, Nix non-FHS `nixos/nix`) without depending on distro-specific shared libraries (`integration-brief.md` §6). PTY allocation works unprivileged; syscall-level fs/network capture (eBPF/ptrace) is deferred because the blueprint→adapter path does not convey the required capabilities today.

---

## 5. Correlation & identity model

`sealantd` mints typed newtype identifiers (plan §8.3) and binds every event to the monorepo's existing correlation keys.

| Identifier | Meaning | Binding |
|---|---|---|
| `RuntimeId` | The daemon instance — one per sandbox+run. | Daemon identity stamped on every event envelope. |
| `ExecutionId` | Carries the monorepo `runId` (== `attemptId`), the per-run correlation key. | `sandbox_runtime_instances.run_id` PK (1:1), `sandboxSshTargetSchema.attemptId` (`integration-brief.md` §2). |
| `sandboxId` | Bound at **config level** (boot payload), not per-event minted. | `sandboxes` table PK; SSH carries it as `sbx-{id}` in the username (`integration-brief.md` §2). |
| `SessionId` | PTY/interactive session correlation. **Minted by sealantd** — no pre-existing format. | Maps to one ssh-gateway shell/exec session. |
| `ProcessId` | Stable logical process id. **Minted by sealantd.** The OS PID is **never** the stable `ProcessId`; PID/PGID/pidfd are recorded separately. | Per managed command. |
| `RequestId` | Control-request correlation and duplicate-request handling. | One per protocol request; one ack per request. |
| `EventId` | Globally unique idempotency / delivery key. | Non-empty string, compatible with `sandboxEventSchema.eventId: NonEmptyTrimmedString` (the only precedent; **no prefix convention**). |
| `Sequence` | Monotonic order within the runtime's sequence domain — order observed/enqueued by Sealant, not kernel causality. | Assigned at the single deterministic sequencing point (§3). |
| `StreamOffset` | Monotonic per-stream byte position for I/O events. | One offset domain per `(processId, streamKind)`. |

Key rules: the only sequence-assignment point per runtime guarantees a total order without producer-side races (plan §5, §15); `StreamOffset` gives a separate, gap-free per-stream byte position even when sequence values interleave across streams (plan §8.4, §12). Every emitted event carries `runId`(=`ExecutionId`) and `sandboxId` so it serializes into the existing `{ eventId, sandboxId, attemptId?, type, occurredAt, message?, data }` envelope (`integration-brief.md` §4).

---

## 6. Fail-open vs fail-closed by subsystem (plan §4.4)

Every subsystem defines explicit degradation. No telemetry loss is silent: whenever data is dropped, truncated, redacted, coalesced, or unavailable, a normalized event or counter is emitted. High-priority lifecycle events get stronger preservation than verbose high-volume events.

| Subsystem | Default | Rationale / on-failure behavior |
|---|---|---|
| Control socket bind (`sealant-control`) | **Fail-closed** | If `/run/sealantd.sock` (0600) cannot bind, or is unreachable at session-open, the sandbox refuses the session (brief req 15). The daemon is the run's evidence authority; no daemon = no run. |
| Config validation (`sealant-runtime-core`) | **Fail-closed** | Invalid config never reports healthy; the daemon refuses to start rather than capture under unknown policy (plan §9). |
| Process exec / control (`sealant-process`) | **Fail-closed** | Process control is the daemon's core duty; an `exec` that cannot start returns a typed error (`process-start-failed`), it does not silently run uninstrumented. |
| PTY sessions (`sealant-pty`) | **Fail-closed** | `pty-allocation-failed` is surfaced; an interactive session is not silently downgraded to an uninstrumented shell. |
| Durable spool (`sealant-eventlog`) | **Fail-closed for Critical** | Critical events spool before delivery; a partial/corrupt record is recovered and reported. Unrecoverable loss is reported explicitly, never swallowed (plan §16). |
| Telemetry delivery sink (`sealant-telemetry`) | **Fail-open (buffer)** | A slow/disconnected sink never blocks producers; events accumulate in bounded queues → spool → retry with backoff. Capture continues. |
| I/O capture (`sealant-process`/`sealant-pty`) | **Fail-open** | On queue pressure, low-priority I/O chunks may be coalesced or dropped with counters; the process keeps running and lifecycle events are preserved (plan §12, §15). |
| Filesystem telemetry (`sealant-fs`) | **Fail-open** | inotify overflow emits `file.watchOverflow` and triggers a rescan rather than aborting the run; coalesces editor temp-file noise (plan §13). |
| Network telemetry (`sealant-network`) | **Fail-open** | `metadata`/`proxy` are best-effort; a `privileged` backend that cannot attach degrades cleanly to a lower mode and reports reduced capability — it never blocks the workload (plan §14.4). |
| Health / metrics (`sealant-runtime-core`) | **Fail-open** | Degradation is reported via `degraded`/`unhealthy` states and concrete reasons; the daemon stays up to keep emitting evidence about its own failure (plan §17). |
