# ADR-0011: Packaging — static musl amd64 binary

## Status

Accepted, 2026-06-20.

## Context

sealantd ships as a binary copied into the workspace image and launched from the
entrypoint (brief §1, §6). The image is built three ways via `distroDefinitions`
in `buildkit-builder.ts` (≈187/212/237): **Fedora 41** (glibc), **Arch** (glibc),
and **`nixos/nix:latest`** (non-FHS, no `/usr/sbin`, nonstandard library layout).
A single artifact must run on all three. A glibc-linked binary risks breaking on
the Nix image's nonstandard layout (brief §6); a **statically-linked musl binary
(`x86_64-unknown-linux-musl`)** is self-contained and safe across all three base
images.

Arch is the only distro built with `--platform linux/amd64`
(`buildkit-builder.ts:1124`, `platformArgs = osFamily === "arch" ? [...] : []`);
Fedora and Nix inherit host arch, but builds are effectively amd64. arm64 is not
a planned matrix yet — it needs cross-compiled binaries plus a blueprint arch
field that does not exist (brief §6). Plan §20 lists Linux x86_64 and arm64
artifacts, `--version`, `--check-config`, `--print-capabilities`, a
BuildKit-friendly build stage + artifact copy step, minimal runtime deps, and
debug symbols or a separate symbol artifact. Plan §20 also cautions: prefer
portable/static artifacts but do not break PTY, NSS, TLS, or privileged
collection just to claim fully static.

The copy/launch seams are exact (brief §1, §6): add `COPY sealantd
/usr/local/bin/sealantd` + `chmod 755` **after `buildkit-builder.ts:1060**` (the
line that copies `entrypoint.sh`), and launch the daemon in the entrypoint
**before the foreground harness command at `:842`** (and before the sshd block
at ~838) so sealantd owns the PTY/process lifecycle. The daemon binds
`/run/sealantd.sock` (`0600`) and needs a writable runtime dir analogous to
today's `$SSH_RUNTIME_DIR`. PTY (`openpty`/`TIOCSWINSZ` via `nix`/`rustix`) works
unprivileged and statically; eBPF/ptrace need capabilities not conveyed today
(brief §6, deferred to ADR-0009's separate collector). The ADR subject ("static
musl amd64") is the packaging half of plan §20.

## Decision

Ship a **single statically-linked `x86_64-unknown-linux-musl` binary** as the
primary `sealantd` (and `sealantctl`) artifact. amd64-first; arm64 deferred
until a blueprint arch field and cross-compile matrix exist (brief §6).

**Why musl-static is safe here.** The daemon's required runtime work — Unix
socket framing, process/PTY lifecycle, in-process telemetry — uses syscalls and
`openpty`/`TIOCSWINSZ`, which the musl static binary handles without distro
shared libs. The plan §20 caveats apply only partially:

- **NSS** — the daemon does not resolve users/hosts via glibc NSS on the hot
  path; auth is owned by the gateway, not sealantd (brief §3). DNS *observation*
  in `metadata` mode reads syscalls/`/etc/resolv.conf`, not NSS plugins. So
  static linking does not break our use.
- **TLS** — not in the default path; `payload`/TLS-intercept is off by default
  and lives in the separate privileged collector (ADR-0009), not the daemon. No
  in-daemon TLS dependency to break.
- **PTY** — works unprivileged and statically (brief §6).
- **Privileged collection** — already split into a separate process (ADR-0009);
  it is not part of this static daemon artifact, so it imposes no linking
  constraint on `sealantd`.

Thus static musl is taken without violating the plan §20 caveat.

**Image integration (exact seams).**

- In `renderContainerfile`, stage `sealantd` into the build context alongside
  `entrypoint.sh` (`writeBuildContext`, ~lines 1079-1098) and add `COPY sealantd
  /usr/local/bin/sealantd` + `RUN chmod 755 /usr/local/bin/sealantd`
  **immediately after `buildkit-builder.ts:1060`** (the `COPY entrypoint.sh`
  line). Build remains `DOCKER_BUILDKIT=1 docker build` then `docker save`
  (lines 1124-1141).
- In `renderWorkspaceEntrypoint`, launch sealantd **before the sshd block (~838)
  and before the foreground harness command at `:842`**, so the gateway's
  upstream shell/exec lands on a sealantd-spawned process and sealantd owns the
  PTY (brief §1). The entrypoint must create a writable runtime dir for the
  `/run/sealantd.sock` (`0600`) socket, analogous to `$SSH_RUNTIME_DIR`, and
  fail closed if the socket is unreachable at session-open (brief §7 req 15).

**CLI surface (plan §20).** The binary provides `--version` (with build
metadata), `--check-config` (validate config, exit non-zero on error), and
`--print-capabilities` (emit the startup capability/feature probe from ADR-0009
without starting the daemon). These let the entrypoint and CI verify the artifact
before it owns a session.

**Runtime deps and symbols.** Minimal runtime dependencies — the static binary
plus a writable runtime dir; no distro packages installed for sealantd. Build
metadata (version, git SHA, target triple) is embedded for `--version`. Debug
info ships as **line-tables-only in the binary or a separate stripped symbol
artifact** (plan §20), keeping the in-image binary small while preserving
symbolication off-image.

## Consequences

Positive:

- One artifact runs across Fedora-41, Arch, and `nixos/nix` (brief §6 req 14)
  with no dependency on distro shared libs or FHS layout; the Nix non-FHS image
  is no longer a special case.
- The copy/launch change is a two-line edit at named seams
  (`buildkit-builder.ts:1060` and `:842`), small to review and to test
  (TST-PKG-\*).
- `--check-config` / `--print-capabilities` let CI and the entrypoint validate
  the binary before it takes over the session, supporting fail-closed (brief §7
  req 15).
- musl-static avoids the glibc-version skew that would otherwise differ across
  the three base images.

Negative:

- musl differs from glibc in allocator and some syscall edge behavior; Linux-only
  paths must be validated inside docker containers (the dev host is macOS, build
  cross-platform), not assumed from a macOS build.
- arm64 is unsupported until a blueprint arch field and cross-compile matrix
  exist; arm64 hosts cannot run this artifact.
- Static linking forecloses glibc NSS/TLS plugins should a future in-daemon
  feature need them; such a feature would force a relink decision or a move into
  the separate collector.
- A separate symbol artifact adds a build output to publish and to keep in sync
  with each binary for symbolication.

## Alternatives considered

- **glibc dynamic binary.** Rejected: risks breaking on the `nixos/nix` non-FHS
  layout and on glibc-version skew across Fedora/Arch (brief §6); needs distro
  libs present.
- **Per-distro binaries (3 artifacts).** Rejected: triples the build/publish
  matrix and the copy logic in `buildkit-builder.ts` for no behavioral gain over
  one static binary.
- **glibc-static.** Rejected: glibc static linking is fragile (NSS warnings,
  partial-static reality) and offers no portability advantage over musl for our
  syscall-only daemon.
- **amd64 + arm64 now.** Rejected: arm64 needs a cross-compile matrix and a
  blueprint arch field that does not exist today (brief §6); amd64-first matches
  the effective build target.
- **Fully static, no exceptions, even for TLS/privileged.** Unnecessary: TLS and
  privileged collection are out of the daemon artifact (off by default / separate
  collector, ADR-0009), so the plan §20 caveat is satisfied without compromise.
