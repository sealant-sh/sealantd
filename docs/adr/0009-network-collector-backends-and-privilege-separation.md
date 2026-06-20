# ADR-0009: Network collector backends and privilege separation

## Status

Accepted, 2026-06-20.

## Context

sealantd runs inside Sealant Linux sandboxes launched by plain `docker run`
through `DockerRuntimeAdapter` (brief §1). The container is unprivileged: PTY
allocation via `openpty`/`TIOCSWINSZ` (the `nix`/`rustix` term features in
`Cargo.toml`) works without elevation, but any syscall- or kernel-level network
capture — eBPF, cgroup socket hooks, netlink/conntrack, packet capture,
transparent proxying — needs Linux capabilities (`CAP_BPF`, `CAP_NET_ADMIN`,
`CAP_NET_RAW`) that **the blueprint→adapter path does not convey today** (brief
§6). The blueprint has no capability or arch field; the adapter calls `docker
run` with no added caps. So the default daemon cannot assume any privilege.

Plan §14 mandates capability-aware network modes and §14.4 specifically directs:
detect kernel features and capabilities at startup, degrade cleanly when a
backend cannot attach, do **not** make the whole daemon permanently privileged
for one optional collector, and consider a separate privileged collector process
with a narrow IPC contract. Plan §14.3 forbids TLS interception / payload capture
by default; plan §20 lists "TLS interception by default" as an explicit non-goal.
The daemon emits evidence only — plan §14.5 leaves it to the TypeScript SDK to
decide whether an observation represents an LLM-used source. The crate that owns
this is `sealant-network` (brief §7: "collectors, DNS, proxy, privileged
backends").

## Decision

Define five capability-aware modes in `sealant-network`, selected by config and
clamped by a startup capability probe:

- **off** — no network observation; the capability is reported as disabled via
  `getCapabilities()` / `--print-capabilities`. No collector threads start.
- **metadata** — default. Best-effort, fully unprivileged: DNS observations,
  local/remote addr+port, protocol, direction, open/close timestamps, byte
  counts where observable, and process/session attribution where observable
  (plan §14.2). In-process instrumentation only (brief §6 favors this).
- **proxy** — an explicit local egress proxy in the daemon process; records
  scheme, host, port, HTTP method/path, status, byte counts, timing,
  process/session attribution when possible. For HTTPS `CONNECT`, record only
  destination host:port — never pretend the encrypted path is known (plan
  §14.3). Still unprivileged.
- **privileged** — eBPF / cgroup socket hook / netlink-conntrack / packet /
  transparent-proxy backends. Runs **only** in a separate privileged collector
  process, never in the main daemon (see below).
- **payload** — TLS interception / response-body / credential capture.
  Policy-gated, off by default, gated behind a separate privacy/security review
  (plan §14.3, §20 non-goal). Requires `privileged` to also be active.

**Startup probe and clean degradation.** On launch, `sealant-runtime-core`
queries effective Linux capabilities and kernel feature availability (BPF
syscall, conntrack/netfilter, cgroup hooks). The configured mode is the
*requested* mode; the *effective* mode is the highest mode the environment
supports. If `privileged` is requested but no capabilities are conveyed (the
default container case, brief §6), the daemon degrades to `metadata`, emits a
single warning to stderr (not the protocol stream, per plan §8.1), and reports
the requested-vs-effective gap honestly through health/capabilities (plan §4.4,
§4.6). A backend that fails to attach degrades the *mode*, never crashes the
daemon.

**Privilege separation.** All privileged/payload backends live in a separate
`sealant-net-collector` process, not in `sealantd`. The main daemon stays
unprivileged. The collector exposes a **narrow IPC contract** over a dedicated
Unix socket (distinct from the SDK control socket `/run/sealantd.sock`, brief
§1): the daemon sends an attach request scoped to the run's cgroup / pid set and
the active capture mode; the collector streams back normalized observations only.
The contract surfaces **no raw packets and no shell**; it is a typed,
length-prefixed channel mirroring the main wire framing (plan §8.1, ADR-0001).
The collector is launched only when the effective mode is `privileged`/`payload`
and capabilities are present; otherwise it is never spawned.

**Normalized output.** Regardless of backend, `sealant-network` emits
`network.sourceObserved` evidence events (plan §14.5) carrying hostname,
resolved IPs, port, scheme when known, URL/path only when actually observable,
first/last observation times, associated process/session identifiers
(`ProcessId`/`SessionId` newtypes, brief §2/plan §8.3), observation method, and a
confidence value. Sequence and per-stream offsets follow the single
deterministic assignment point (plan §8.4). The daemon does not classify a
source as "used by an LLM" — that judgement is the SDK's (plan §14.5).

## Consequences

Positive:

- Default deployment is unprivileged and works unchanged on the Fedora, Arch,
  and `nixos/nix` base images (brief §6) with no blueprint/adapter changes.
- A capability regression (caps removed, kernel feature missing) degrades the
  mode and is reported honestly instead of failing the run (plan §4.4/§4.6).
- The large attack surface of eBPF/netlink/packet code is isolated in a separate
  process; a bug there cannot escalate the main daemon, which holds the
  SDK/control socket and PTY/process lifecycle.
- Adding `privileged`/`payload` later is a config + capability-grant change, not
  a daemon rewrite, because the mode ladder and IPC contract already exist.

Negative:

- `metadata` mode cannot see in-kernel connection state, so attribution and byte
  counts are best-effort and may be incomplete; confidence must be reported.
- The separate collector adds a second process, a second socket, and the IPC
  contract to maintain, version, and test (TST-NET-\*).
- Effective behavior is environment-dependent; consumers must read
  `getCapabilities()` rather than assume a fixed mode, which complicates SDK and
  test expectations.
- `payload`/TLS-intercept remains undelivered until the separate privacy review
  and capability-conveyance work land; the mode exists in the schema but is
  inert by default.

## Alternatives considered

- **Single privileged daemon.** Run everything (PTY, control socket, eBPF) in one
  privileged process. Rejected: plan §14.4 explicitly forbids making the whole
  daemon permanently privileged for one optional collector, and it would broaden
  the blast radius of the process that owns the SDK socket.
- **Privileged-by-default, drop on failure.** Request caps and silently fall back.
  Rejected: caps are not conveyed today (brief §6), so the common path is the
  fallback path; better to make `metadata` the explicit default and surface the
  gap.
- **Mandatory egress proxy for all traffic.** Force every connection through the
  proxy. Rejected: breaks transparent network use, can't see HTTPS payloads
  anyway (only `CONNECT` host:port, plan §14.3), and is heavier than metadata for
  the common case. Offered as `proxy` mode, not forced.
- **TLS interception in scope now.** Rejected: plan §14.3 and §20 make it a
  policy-gated non-goal pending a separate review; shipped as the inert `payload`
  mode.
- **FFI / in-Node capture.** Rejected: plan §19 mandates IPC as the language
  boundary and forbids Rust↔Node FFI as the runtime-control architecture.
