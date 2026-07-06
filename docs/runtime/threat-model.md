# sealantd Threat Model

Scope: the `sealantd` daemon as it runs **inside** a Sealant Linux workspace container, the
length-prefixed JSON control socket it exposes, and the evidence trail it emits. Grounded in
plan §18 (Security and threat model) and the deployment reality in the integration brief §6.

This document does not invent a privilege boundary that the deployment does not have. Where a
mitigation is partial, the residual risk is stated plainly (plan §18 callout: *do not describe
same-namespace observation as tamper-proof unless the architecture actually provides a stronger
privilege or isolation boundary*).

## 1. Trust assumptions

Per plan §18: **assume workspace workloads are buggy, hostile, evasive, or intentionally
resource-exhausting.** The daemon is the recorder, not the adversary's keeper.

Deployment reality (brief §6):

- Containers launch via plain `docker run` through `DockerRuntimeAdapter`
  (`packages/workspaces/src/runtime/docker-runtime-adapter.ts`). There is **no rootless-by-default,
  no user-namespace remap, no seccomp/AppArmor profile** conveyed from the blueprint→adapter path.
- PTY allocation (`openpty`/`TIOCSWINSZ`) works unprivileged, but **eBPF/ptrace-class syscall capture
  needs capabilities the blueprint→adapter path does not convey today** (brief §6). The architecture
  therefore favors in-process instrumentation (pipe/PTY/proxy/inotify capture), which is *cooperative*,
  not *enforced*.
- sealantd ships as a **single statically-linked musl linux/amd64 binary** at `/usr/local/bin/sealantd`,
  launched by the generated entrypoint before the harness foreground command
  (`packages/workspaces/src/buildkit/buildkit-builder.ts` ~line 838/842), owning a writable runtime dir
  for its socket (default `/run/sealantd.sock`, perms `0600`).
- The container's default UID is **root** (the SSH endpoint resolves to `ssh://root@…`,
  `docker-runtime-adapter.ts:370,435`). Unless sealantd explicitly drops the child to a separate
  unprivileged UID (plan §18 "Security design goals"), **daemon and workload share one UID, one PID
  namespace, one network namespace, and one filesystem.** This single fact bounds every mitigation below.

**Consequence stated up front:** when the workload runs as root in the same namespaces as the daemon
(the default), same-namespace observation is **not tamper-proof**. The evidence trail is trustworthy
exactly to the extent that the workload cannot reach the daemon's memory, descriptors, socket, and
spool — and a same-UID root workload can reach all of them. The strong-isolation story (§4) requires a
privilege/namespace boundary that does not exist in the current adapter path.

## 2. Threat matrix (plan §18)

Each row maps a plan §18 threat to concrete mitigations and the honest residual risk under the
unprivileged-docker reality of brief §6. Mitigations are tagged with requirement AREA codes
(SEC, CTRL, PROC, IO, SPOOL, NET, PIPE, CFG, HEALTH).

| # | Threat (plan §18) | Mitigations | Residual risk (brief §6 reality) |
|---|---|---|---|
| 1 | **Child kills daemon** — does UID/capability separation prevent signaling? Degradation story? | Run the child under a *separate unprivileged UID* and the daemon under a protected identity (plan §18 design goals; **REQ-SEC**); deliver signals only to the child's own process group, never accept a child-originated signal toward the daemon (**REQ-PROC**); set `PR_SET_DUMPABLE=0` and ptrace restrictions on the daemon (plan §18). Health endpoint + entrypoint **fail-closed**: if the socket is unreachable at session-open the workspace refuses the session (brief §7 req 15; **REQ-HEALTH**). | **High when workload is root / same UID.** A root or same-UID child can `kill(daemon_pid, SIGKILL)` directly — no UID separation exists in the default `docker run`. Degradation is honest: on daemon death the gateway's session-open fails closed, so the run is *recorded-or-refused*, never *silently unrecorded*. The daemon cannot be made un-killable in a shared privileged namespace. |
| 2 | **Child reads secrets** — are env vars, descriptors, files, proc entries, and logs isolated? | Explicit child base env, never `std::env::vars()` passthrough; strip telemetry creds, control tokens, internal endpoints, spool keys, debug secrets (plan §18 Environment isolation; **REQ-SEC**, **REQ-CFG**). Set **close-on-exec** on all daemon-only descriptors so the control socket / spool / log fds never leak across `exec` (plan §18; **REQ-SEC**). Secrets live only in daemon memory, never on the child's argv, env, or inherited fds. Tracing diagnostics never duplicate secrets (§3 below). | **High when workload is root / same namespace.** A root child can read `/proc/<daemon_pid>/environ`, `/proc/<daemon_pid>/maps`+`/mem`, and `/proc/<daemon_pid>/fd/*`, defeating env/descriptor isolation entirely. close-on-exec and env stripping fully defeat the *non-root, same-UID* and *inheriting-child* cases (the common ones); they do **not** defeat a root peer with `/proc` access. Mitigated only by dropping the child below the daemon's UID. |
| 3 | **Unauthorized control client** — how are socket mode, ownership, peer credentials validated? | Bind `/run/sealantd.sock` at `0600` owned by the daemon UID before accepting any request (brief §7 req 1; **REQ-CTRL**, **REQ-SEC**); validate peer credentials via `SO_PEERCRED` (uid/gid/pid) on connect and reject non-allowlisted peers (plan §18; **REQ-CTRL**). Enforce the protocol version handshake on connect (brief §7 req 11; **REQ-PROTO**). Note: end-user auth is **not** sealantd's job — the ssh-gateway owns publickey auth and binds `workspaceId` (brief §3); sealantd trusts the already-authenticated upstream/control caller. | **Medium-High.** `0600` + `SO_PEERCRED` stop any *non-owner* UID. But a same-UID (root) workload passes ownership and peer-cred checks by construction — it is indistinguishable at the kernel level from the legitimate gateway caller. There is no cryptographic client identity on the local socket, so in the shared-UID case a workload can open the control socket and inject/replay control requests. |
| 4 | **Fake telemetry injection** — can workloads write directly to the spool or event transport? | Final event **sequence values are assigned at one deterministic point per runtime** (canonical fact) inside the daemon; I/O events carry a monotonic per-stream `streamOffset`. Workloads have **no protocol path to mint events** — they produce bytes that the daemon *observes* and wraps; they cannot submit pre-formed events. Event ids/`Sequence`/`StreamOffset` are daemon-minted newtypes (canonical facts), correlated to `runId`(=attemptId)+`workspaceId` (brief §7 req 7; **REQ-IO**, **REQ-PROTO**). | **High when workload is root / same UID.** A child cannot inject *through the protocol*, which closes the cooperative path. But a same-UID peer that can write the spool file or open the control socket (threats 3, 5) can fabricate or reorder events directly, bypassing the single sequencing point. The single-deterministic-sequencer property guarantees *internal consistency of what the daemon recorded*, not *authenticity against a same-privilege forger*. |
| 5 | **Spool tampering** — are ownership, checksums, permissions, corruption events sufficient? | Spool files owned by the daemon UID with restrictive mode; per-record/per-segment checksums; emit explicit **corruption events** on checksum mismatch rather than silently dropping (plan §18; **REQ-SPOOL**). Append-only write discipline from the single sequencer point. | **High when workload is root / same UID.** Checksums detect *accidental* corruption and *non-owner* tampering, and the corruption event makes tampering *visible* rather than silent. They do **not** prevent a root/same-UID workload from rewriting both the record and its checksum. Tamper-evidence, not tamper-resistance. True integrity needs the spool written across a privilege boundary (e.g. streamed out of the namespace) the deployment lacks. |
| 6 | **Resource exhaustion** — limits for output, forks, file events, sockets, memory, disk? | Enforce **max frame size before allocation** on every inbound JSON frame (canonical wire fact; **REQ-PROTO**, **REQ-PIPE**); bound per-stream output (flood caps), fork/PID counts, inotify/file-event rates, open sockets, in-memory buffer and spool-disk budgets (plan §18 "fork bombs, output floods, event storms, oversized protocol frames"; **REQ-IO**, **REQ-PROC**, **REQ-FS**, **REQ-SPOOL**, **REQ-NET**). On limit breach, emit a typed throttle/limit event and degrade rather than OOM-kill the daemon. | **Medium.** sealantd can cap *its own* buffers and *its own* spool, and can record that a flood occurred. It cannot, without cgroup control it does not own (brief §6), stop a root workload from exhausting container-wide CPU/PID/memory/disk out-of-band. Daemon self-protection is achievable; container-wide enforcement is the orchestrator's job, not sealantd's. |
| 7 | **Proxy bypass** — enforceable in the current network namespace and privilege mode? | Offer an **explicit egress proxy** with observable HTTP/CONNECT metadata as a capture *option*, and set proxy env (`HTTP_PROXY`/`HTTPS_PROXY`) in the explicit child base env (plan §14; **REQ-NET**, **REQ-PIPE**). Record the active capture method per event so consumers know whether a flow was proxied or merely inferred. | **High — bypass is fully possible.** In-process/explicit-proxy capture is cooperative: a workload simply ignores `HTTP_PROXY`, opens raw sockets, or unsets the env. **Transparent enforcement (iptables redirect, netns, eBPF/socket hooks) needs capabilities the blueprint→adapter path does not convey** (brief §6). Therefore the proxy yields *evidence of cooperating traffic*, not an enforced egress boundary. This must be stated to consumers, not implied as complete. |
| 8 | **Root workload** — what guarantees become impossible when workload and daemon share a privileged namespace? | The only real mitigation is to **remove the shared-privilege condition**: drop the child to a separate unprivileged UID (plan §18 design goal), and/or have the orchestrator run the container rootless / user-namespaced. Absent that, minimize blast radius (close-on-exec, `PR_SET_DUMPABLE`, restrictive socket/spool modes) knowing they are bypassable by root. | **This is the worst case and the default.** With a root workload sharing the daemon's UID, PID, net, and mount namespaces, threats 1–5 all degrade to High: the workload can signal/kill the daemon, read its memory/fds/env via `/proc`, open its socket, and rewrite its spool. **No same-namespace mechanism makes the trail tamper-proof against root.** The evidence trail is then *best-effort and tamper-evident*, explicitly not *tamper-proof* (plan §18 callout). |

## 3. Environment isolation rules (plan §18)

Concrete rules the `sealant-process` spawn path and `sealant-control` config must enforce
(**REQ-SEC**, **REQ-CFG**; tested as **TST-SEC-*** including the brief §7 "Secret-like output redaction"
and "Daemon secrets do not leak through env or inherited descriptors" gates):

1. **Explicit child base environment.** Construct the child env from an allowlist — never blindly forward
   `std::env::vars()` (plan §18). The child sees only what the run needs (e.g. `PATH`, `HOME`, `TERM`,
   the run's declared variables), plus optional proxy vars when proxy mode is on (§2 row 7).
2. **Strip all runtime secrets** from the child env: telemetry credentials, control tokens, internal
   endpoints, spool keys, debug secrets (plan §18). These exist only in daemon memory.
3. **Validate environment keys** before they enter the child env (reject malformed/oversized/duplicate keys).
4. **Emit only allowlisted, redacted environment metadata** in the evidence trail — the daemon records
   *that* an env var existed (by allowlisted name), never an unredacted secret value.
5. **close-on-exec on every daemon-only descriptor** (control socket, spool fds, log sink) so no daemon
   resource is inherited across the child's `exec` (plan §18 design goals).

## 4. Logging vs. telemetry separation (plan §18)

Two strictly separate channels; secrets cross neither into the other:

- **Diagnostics (logging):** structured `tracing` for daemon operations, written to **stderr or a dedicated
  logging sink** (plan §18). This is for operators, not the product. It must **never** duplicate secrets
  (plan §18) and is governed by the stdio rule that protocol output goes only to stdout while human
  diagnostics go only to stderr (plan §6/§18).
- **Product telemetry (the evidence trail):** flows **only** through the typed event pipeline — the
  length-prefixed JSON protocol whose schema is the Rust serde structs (schemars → generated TS types),
  carrying daemon-minted ids correlated to `runId`+`workspaceId` (brief §4/§7). Workload bytes travel as
  base64 with an original byte count (canonical fact); they are never assumed UTF-8 and never logged as
  diagnostics.

The separation matters for this threat model: a secret redaction failure in *one* channel must not leak
through the *other*. Tracing is not a backdoor for telemetry data, and telemetry is not a sink for daemon
debug strings. **Never duplicate secrets into diagnostic logs** (plan §18).

## 5. Honest limitation statement

Restating the plan §18 callout in operational terms, because it is the single most important property of
this system to communicate:

> **Same-namespace observation by sealantd is not tamper-proof.** It is tamper-*evident* (checksums,
> corruption events, a single deterministic sequencer, fail-closed session-open) and reliable against
> *buggy* and *non-privileged* workloads. It is **not** reliable against a **root workload sharing the
> daemon's UID and namespaces** — the default in the current `docker run` adapter path (brief §6). Such a
> workload can signal the daemon, read its memory/descriptors/env via `/proc`, connect to its control
> socket as a same-UID peer, and rewrite its spool and checksums.

A stronger guarantee requires a real privilege or isolation boundary that the architecture must actually
provide — at minimum dropping the child to a separate unprivileged UID (plan §18 design goal), and ideally
rootless/user-namespaced containers or out-of-namespace spool egress. Until such a boundary exists in the
blueprint→adapter path, sealantd's trail must be presented to consumers as **best-effort, tamper-evident
evidence — explicitly not a tamper-proof audit log.**
