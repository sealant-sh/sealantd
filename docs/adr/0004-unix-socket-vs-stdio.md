# ADR-0004: Unix socket versus stdio responsibilities

## Status

Accepted, 2026-06-20

## Context

sealantd is the control and telemetry entry point inside a Sealant sandbox. The
plan fixes the transport split (plan §8.1): "Primary transport: Unix domain
socket"; "Optional transport: stdio adapter for wrappers and deterministic
integration tests"; "When using stdio, protocol output goes only to stdout and
human diagnostics go only to stderr"; "Restrict socket permissions and validate
Linux peer credentials where appropriate"; "Handle stale socket paths without
blindly unlinking arbitrary files." The Unix-socket-vs-stdio split is a mandatory
ADR subject (plan §6).

The integration brief grounds where this transport plugs in. sealantd replaces or
wraps the in-container `sshd` / `sandbox-ssh-shell` foreground role established in
`renderSandboxEntrypoint` (`buildkit-builder.ts` ~lines 819-840) and should "bind
a Unix socket (e.g. `/run/sealantd.sock`, perms `0600`) as the SDK/control entry
point" (integration brief §1). Authentication is **owned entirely by the ssh
gateway**, not sealantd: `gateway-server.ts` enforces publickey-only auth, derives
`sandboxId` from the `sbx-{id}` username, and connects upstream with a single
gateway-held key (integration brief §3). sealantd therefore does not authenticate
end users — it trusts the already-authenticated control-socket caller. The
gateway session verbs (`openSession`/`shell`, `exec`, `writeStdin`, `resizePty`,
`signal`, `closeSession`) are what the socket API services (integration brief §3;
plan §8.5 required commands; plan §19 SDK shape). The sandbox must **fail closed**
— refuse the session — if the socket is unreachable at session-open time
(integration brief §7, requirement 15). Diagnostics use structured `tracing` and
must never share a channel with product telemetry (plan §18 logging-vs-telemetry).

## Decision

**Primary transport: a Unix domain socket.**

- Default path `/run/sealantd.sock`, mode **`0600`**, bound before any control
  request is accepted (integration brief §7, requirement 1; integration brief §1).
- **Peer-credential checks** via `SO_PEERCRED` (Linux) gate control callers
  (plan §8.1, §18; brief §3 — sealantd trusts the connection rather than
  re-authenticating users, so the socket boundary is the access boundary).
- **Stale-socket handling is safe**: a stale path is unlinked only after
  confirming it is a socket that no live daemon owns — never a blind unlink of an
  arbitrary path (plan §8.1).
- The socket lives in a writable runtime dir analogous to today's
  `$SSH_RUNTIME_DIR` (integration brief §6); the daemon owns it.
- All protocol traffic — length-prefixed JSON frames (ADR-0002), commands and the
  event stream — flows over this socket. This is the language boundary; Rust↔Node
  FFI is explicitly not the architecture (plan §19).

**Optional transport: a stdio adapter** for wrappers and deterministic
integration tests (e.g. `sealantctl`, plan §7).

- **Protocol output goes only to stdout**; **human diagnostics go only to stderr**
  (plan §8.1, §18). The same framing (ADR-0002) is used on stdout.
- The stdio adapter is selected explicitly (a flag/mode on the binary); it does
  not change the protocol, only the byte channel. It makes integration tests
  deterministic by removing socket setup/teardown and peer-cred plumbing from the
  test path (plan §19 end-to-end tests through the real daemon).

**Diagnostics discipline (both transports).** Daemon operational logs use
structured `tracing` to stderr / a dedicated logging sink; product telemetry only
ever travels the typed event pipeline. Secrets are never duplicated into
diagnostics (plan §18 logging-vs-telemetry).

## Consequences

**Positive**

- `0600` + peer-credential validation makes the socket the access boundary,
  directly answering the "unauthorized control client" threat (plan §18 threat
  matrix) without sealantd re-implementing the gateway's auth (brief §3).
- The session API maps 1:1 onto the gateway verbs the brief enumerates
  (`openSession`, `writeStdin`, `resizePty`, `signal`, `closeSession`;
  integration brief §3), so the gateway's upstream shell/exec lands on a
  sealantd-spawned process.
- The stdio adapter gives deterministic, socket-free integration tests and a
  wrapper path, while the strict stdout=protocol / stderr=diagnostics rule keeps
  the two channels uncorrupted (plan §8.1, §18).
- Fail-closed-on-unreachable-socket (brief §7) is enforceable at one well-defined
  bind point.

**Negative**

- Two transports mean the control/dispatch layer (`crates/sealant-control`, plan
  §7) must be transport-agnostic and both paths must be tested, or the stdio
  adapter silently rots.
- `SO_PEERCRED` is Linux-specific; the macOS dev host cannot exercise peer-cred
  checks, so that path is validated only inside Linux docker containers
  (integration brief Linux-first / dev-on-macOS note).
- A single `0600` socket trusts every caller that passes the peer-cred gate
  equally — there is no per-caller capability scoping beyond UID/credential
  match; finer authorization would need an added token layer.
- Any stray library write to stdout in stdio mode corrupts the protocol stream;
  the diagnostics-to-stderr rule must be enforced, not assumed.

## Alternatives considered

- **stdio as the primary (or only) transport.** Rejected: a long-lived daemon
  that the gateway connects into for the lifetime of a run needs a stable,
  permission-controlled rendezvous with peer-credential checks — a bound socket
  (plan §8.1). stdio has no peer-credential story and ties the daemon's lifetime
  to a single parent's pipes, which does not fit the "bind before accepting
  requests, fail closed if unreachable" model (brief §7).
- **TCP / loopback socket.** Rejected: it widens the attack surface inside the
  sandbox network namespace and cannot use filesystem permissions or
  `SO_PEERCRED`; the Unix socket's `0600` + peer-cred gate is strictly tighter
  (plan §8.1, §18).
- **Drop the stdio adapter entirely.** Rejected: it is the deterministic harness
  for integration tests and the wrapper-mode escape hatch the plan calls for
  (plan §8.1, §19); keeping it as an explicit, protocol-identical mode costs
  little because it reuses the same framing and dispatch.
