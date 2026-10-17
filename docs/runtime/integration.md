# Consuming sealantd from the monorepo

sealantd ships **two artifacts** that the `sealant-sh/sealant` monorepo consumes through different
channels — the daemon **binary** runs inside each workspace container; the **TypeScript SDK** runs in
the orchestrator that drives workspaces over the control socket.

## 1. The daemon binary → multi-arch image (GHCR)

A `vX.Y.Z` tag triggers `.github/workflows/release.yml`, which builds a static, multi-arch image
and publishes it once, as `ghcr.io/sealant-sh/sealantd:X.Y.Z` (see [Stable releases](#stable-releases)).
The runtime layer is `scratch` + one static binary.

Bake it into the workspace image with a single `COPY --from` — buildx selects the matching arch
automatically for each target platform:

```dockerfile
# in the workspace image the buildkit builder assembles
COPY --from=ghcr.io/sealant-sh/sealantd:X.Y.Z /usr/local/bin/sealantd /usr/local/bin/sealantd
```

Pin by version (or by `@sha256:` digest for full reproducibility). `:latest` and `:0.19` are frozen
at 0.19.0 and are not a supported way to consume sealantd: no release moves them. Launch it in the
workspace with a socket on a shared path, e.g.:

```sh
sealantd --socket /run/sealantd.sock --workspace /workspace --watch-filesystem --network-proxy
```

When the controller runs on another host (Kubernetes), add the opt-in mutual-TLS WebSocket
frontend beside the socket — see [ADR-0013](../adr/0013-websocket-control-transport.md):

```sh
sealantd --socket /run/sealant/control.sock --workspace /workspace \
  --wss-listen 0.0.0.0:7443 --wss-cert /run/sealant/tls/tls.crt \
  --wss-key /run/sealant/tls/tls.key --wss-client-ca /run/sealant/tls/ca.crt
```

or, under `sealantd boot`, `SEALANT_CONTROL_WSS_LISTEN`, `SEALANT_CONTROL_WSS_CERT`,
`SEALANT_CONTROL_WSS_KEY`, `SEALANT_CONTROL_WSS_CLIENT_CA` (and optionally
`SEALANT_CONTROL_WSS_MAX_CONNECTIONS`). Without these the listener does not exist.

Run it as the **same uid** as the controlling process so peer-credential validation passes
(`SO_PEERCRED`; the socket is also `0600`).

### Without a registry (alternative)

`scripts/build-release.sh` emits `dist/sealantd-{amd64,arm64}`; attach them to a GitHub Release and
`curl` the right arch in the workspace Dockerfile. Simpler infra, but you own arch selection +
checksum verification.

## 2. The TypeScript SDK → npm

`@sealant/runtime-protocol` (typed wire codec) and `@sealant/runtime-client` (the `SealantClient`)
publish to npm from the same tag, after the image (see [Stable releases](#stable-releases)). The
client depends on the protocol at exactly the same version. npm trusted publishing authenticates the
publish (OIDC, with provenance); there is no npm token. Versioning: the npm **major** tracks the wire
`schemaVersion`, so a breaking wire change is loud at the dependency level.

Types are **Buf-generated** (protobuf-es) from `sealant.proto` and committed under
`packages/runtime-protocol/src/gen/` — the schema is baked into the code, so the package is
self-contained (no runtime `.proto`). Both packages build to `dist/` (ESM + `.d.ts`) via `tsc`.

```sh
pnpm add @sealant/runtime-client
```

```ts
import { SealantClient } from "@sealant/runtime-client";
import { RuntimeState, StreamKind } from "@sealant/runtime-protocol";

const client = await SealantClient.connect("/run/sealantd.sock");

const health = await client.health();          // typed: HealthReport
if (health.state === RuntimeState.HEALTHY) {
  const events = client.events();               // AsyncIterable<EventEnvelope>
  const { processId } = await client.exec({ executable: "/bin/echo", args: ["hi"] });

  for await (const event of events) {
    // discriminated union — the compiler narrows `value` per case
    if (event.payload.case === "ioChunk" && event.payload.value.stream === StreamKind.STDOUT) {
      process.stdout.write(event.payload.value.content ?? new Uint8Array());
    }
    if (event.payload.case === "processExited") break;
  }
}
```

Errors throw `SealantError` with a typed `ControlErrorCode`. The full command surface is reachable
via `client.request({ case, value })` for commands without a sugar method.

> Optional next layer: an Effect-native surface (methods as `Effect`, events as a `Stream`, a scoped
> connection) for the Effect-TS monorepo. The protobuf-es types above are the schema it would wrap.

## Version discipline

One git tag drives both artifacts (image tag + npm version) so a deployment pins a single,
consistent `(binary, SDK)` pair.

## Prereleases from main

Every main commit whose `ci` run passed also publishes both artifacts, under **separate names**, as
one prerelease version, `B-next.N` (`.github/workflows/next.yml`, ADR 0015 in sealant-sh/mend). N is
the commit's whole history (`git rev-list --count`); B is the larger of what the pending changesets
would release and the base of the highest next build already published above the last stable tag
(`node scripts/next-version.mjs --package packages/runtime-client --npm @sealant/runtime-client-next`).
`ci` never cancels a main push, and `next` runs one at a time, queued (`queue: max`) in the order
their `ci` runs passed. `next` only moves forward: an older commit whose `ci` passed after a newer
commit's published is refused.

- `ghcr.io/sealant-sh/sealantd-next:0.20.0-next.N`, amd64 and arm64.
- `@sealant/runtime-protocol-next` and `@sealant/runtime-client-next` `0.20.0-next.N` on npm's
  `next` dist-tag; the client depends on the protocol through an exact alias,
  `"@sealant/runtime-protocol": "npm:@sealant/runtime-protocol-next@<version>"`.

The image tag is written once, from the index this run built. `image-tag` takes that index's digest
from `imagetools create --dry-run`, which prints the exact bytes the create pushes, before it writes
anything. It then reads the version tag. The tag is absent only when the registry answers exactly
`ERROR: <ref>: not found` and prints nothing else. Any other failed read fails the job. A tag
already at this run's digest is left alone, and a tag at any other digest is refused, because that
version is spent. After a create, the job reads the tag again and that read decides. A create that
reported an error but left this run's digest passes with a warning. A create that exits 0 but
reports a digest other than this run's fails at once, before the re-read. Re-run only the failed
jobs, while the run's artifacts are still kept: a full re-run rebuilds the images, and their index
is refused if the rebuilt bytes differ (identical bytes are a no-op). Manual or external writes to
the tag are outside this check (`scripts/next-tag.test.mjs`).

The `next` trusted publisher is registered only on the two `-next` packages, so nothing in that
workflow can publish `@sealant/runtime-*`. Images have no such boundary: a job with
`packages: write` can push `ghcr.io/sealant-sh/sealantd` too (GHCR cannot scope it), and any of the
repository's writers can run a branch workflow that requests it, code-owner review or not. The image
jobs' actions and BuildKit are pinned, and Core pins sealantd by `tag@sha256:…`, which keeps out a
tag moved after the pin. Only `publish` holds the npm credential; it installs nothing, runs no
repository code, refuses an artifact holding anything but the expected tarballs, runs npm from an
empty directory, and publishes a tarball it rebuilt from npm's own reading with an allowlisted
manifest.

Core pins a prerelease by exact version when it needs a daemon change before sealantd releases:
`ghcr.io/sealant-sh/sealantd-next:<version>@sha256:<digest>` (Core's `tooling/scripts/pin-sealantd.mjs`
writes it) and the runtime packages as exact aliases
(`"@sealant/runtime-client": "npm:@sealant/runtime-client-next@<version>"`). Core's recovery check
treats a `sealantd-next:X.Y.Z-next.N` image of a version after 0.19.0 like a release.

To release: merge the Version Packages pull request and **freeze main until the tag**; Core pins
that commit's next build; then tag that same commit. Core refuses to cut a stable release while it
pins a prerelease, so this tag comes first. The whole order is in sealant-sh/mend
`docs/operations/next-channel.md`. The release refuses while an npm prerelease of the version came
from a commit the tag leaves out, which is what a merge during the freeze produces.

## Stable releases

A `vX.Y.Z` tag runs `.github/workflows/release.yml` on GitHub-hosted runners:

1. `stable-tag` refuses anything but a plain `vX.Y.Z` tag, an alias dependency in the published
   packages, a next build of the version from a commit the tag leaves out, and a commit whose `ci`
   push run on main did not pass (below).
2. `build` builds each platform on its own native runner and pushes it by digest, with no tag.
   `merge` stages the two as one index under this run's own tag, `staging-<run>-<attempt>`, and
   checks the index maps `linux/amd64` to the amd64 build and `linux/arm64` to the arm64 build,
   and holds nothing else. `pack`, which holds no credential, builds both packages, packs them (the
   client's `workspace:*` dependency becomes this exact version), normalizes each tarball once and
   checks it as the publisher will. `release-manifest` records the version, the commit, the index
   and platform digests, and each tarball's sha512 and integrity. The manifest and the tarballs are
   kept for 90 days.
3. `identity` runs on each arch: it reads the staged index by the digest the manifest records,
   requires the digest it maps this arch's platform to (what a consumer of `:X.Y.Z` would pull) to
   be this arch's build as its build job and the manifest record it, pulls that digest, and checks
   that a container of it runs exactly the image ID the pull gave, that its labels carry
   this version, commit and repository, and that `sealantd --version` reports what the tagged
   commit's `Cargo.toml` says. The workspace version there is `0.0.0`, which the release flow does
   not stamp, so today the daemon reports `sealantd 0.0.0` and the version label is what names the
   release; a `Cargo.toml` that says any version but `0.0.0` or this release's is refused.
4. `finalize-images` writes `:X.Y.Z` from the checked index, under the lock below. It first reads
   that index by its digest and binds its platforms again, as `merge` and `identity` did: each
   arch's platform must map to the build digest the manifest records for it. It reads the tag
   first: absent only when the registry answers exactly `ERROR: <ref>: not found`, already this
   run's index is done, any other digest is refused because the version is spent. After a create
   it reads the tag again, and that read decides.
5. `npm` publishes after `finalize-images`, so every stable runtime package has its daemon at
   `:X.Y.Z`. It holds only `id-token: write`, in the `release` environment, and checks out,
   installs and builds nothing. It refuses an artifact holding anything but the two tarballs, a
   manifest that is not this release's, a tarball whose sha512 is not the manifest's, and a tarball
   that is not already normalized (pacote reads it; nothing rewrites it). It then reads the stable
   floor (below) and runs `npm publish <tarball>` from an empty directory, the protocol first, and
   reads each version's `dist.integrity` back: any integrity but the manifest's is an incident.

`finalize-images` and `npm` are the only jobs that write a stable channel, and each queues on the
job-level lock `sealantd-release-channel` (`cancel-in-progress: false`, `queue: max`), never
cancelled. The lock is held per job, not across a whole release, so `npm` reads the floor inside it.

**The stable floor.** The floor is the higher of npm's `latest` for `@sealant/runtime-protocol` and
for `@sealant/runtime-client`, compared as numbers. GitHub's latest release and the image's
`:latest` label are not markers: there is no release, and `:latest` is frozen. A release above the
floor publishes both packages. A release at the floor is a retry: it republishes nothing and moves
no dist-tag, checks each version npm holds is this run's tarball, and publishes the client only when
the protocol from this run is already there (an attempt that stopped between the two). A release
below the floor publishes nothing, so a backport such as 0.19.1 after 0.20.0 is refused; publishing
one under its own dist-tag is a decision not yet made. A `latest` that cannot be read, or is not a
plain `X.Y.Z` with at most nine digits per part, fails the job.

**Identity checks, not acceptance.** The identity checks prove the staged index is the build this
tag describes and that its daemon starts on both arches. They do not exercise the runtime contract.
A sealantd image is accepted through Core's pin: Core resolves `ghcr.io/sealant-sh/sealantd:X.Y.Z`
to its digest (`tooling/scripts/pin-sealantd.mjs`), its release refuses any sealantd that is not
pinned as `X.Y.Z@sha256:…`, and its CI and release `workspace-e2e` run against exactly that pinned
digest (since sealant#368) before Core ships. Core takes the runtime packages through its
`@sealant/runtime-*` ranges and exercises them in the same runs. A sealantd release Core cannot
accept is fixed by a new sealantd version.

**The `ci` gate.** `stable-tag` lists the `ci` workflow's runs of the tagged commit and requires one
that is a push to this repository's main and concluded `success`, the signal Next trusts through
its `workflow_run` trigger. It covers the Rust daemon tests and the Node package tests, which the
release does not run. A failed read is retried, then fails the release; it is never taken for "no
run". The signal is only as trustworthy as the runners `ci` uses: today its `rust` and `node` jobs
run on the box's persistent runner VMs, which keep state between jobs, so a job from an earlier pull
request could make a later run report success without running the tests honestly. That is decision
D1/D2 in the CI plan. Once D1 (per-job rollback to a clean golden image) is live, the `ci` signal
comes from a VM that starts clean for every job, and this section should say so.

**Tags that never move.** No job writes `:latest` or `:X.Y`. They stay at 0.19.0, where the old
pipeline left them, and nothing in Core, Mend or sealantd reads them: every consumer pins a version
or a digest, and Core's release guard refuses anything else. They cannot be deleted without
deleting the GHCR package version that also carries `:0.19.0`, which Core pins by digest.

**No GitHub release.** sealantd publishes none, and nothing installs sealantd from one.

**The dry run.** Dispatch `release.yml` with `dry_run` to check a release without publishing
anything. Its version is derived, never given: `packages/runtime-client`'s version, then
`-dryrun.<run id>.<attempt>`. It builds both platforms to archives, assembles the index in a
registry on the job's loopback, packs both packages, writes the manifest, and runs the identity
checks on archives it loads after checking them against the manifest. Nothing is pushed to any
registry outside the run: the only push is to the throwaway registry inside `archive-merge`'s own
job. `build`, `merge`, `finalize-images` and `npm` are skipped, so no job holds
`packages: write` or an id-token. A commit without a passed `ci` run is reported as a warning and in
the run summary instead of failing the dry run. A tag carrying a dry-run version is refused before
anything builds, and every job that publishes first refuses any version but its own tag's plain
`X.Y.Z`.

**Re-running a release run.** Re-run failed jobs, while the run's artifacts are kept (the platform
and index digests for a day, the release manifest and tarballs for 90 days):

| What happened | What re-running the failed jobs does |
| --- | --- |
| `stable-tag` refused a commit whose `ci` had not passed yet | Re-run it once `ci` has passed; nothing was built. |
| `build` or `merge` failed | Nothing final was written. The re-run stages a new `staging-<run>-<attempt>`. |
| `pack`, `release-manifest` or `identity` failed | Nothing final was written. The re-run uses the index this run already staged. |
| `finalize-images` failed after its create | The read finds this run's index and passes, with a warning if the create had reported an error. Absent, unreadable or another digest fails. |
| `:X.Y.Z` exists at this run's index; `npm` failed before publishing | `finalize-images` does nothing; `npm` publishes. |
| The protocol published, the client did not | The floor is now this version, so `npm` retries: the protocol verifies as this run's tarball and the client publishes. |
| Both published | `npm` verifies both and publishes nothing. |
| A newer release published while this one waited | `npm` refuses below the newer floor. This run's `:X.Y.Z` may exist; nothing reads `:latest`, so that moves nothing. |

Re-running **all** jobs after `:X.Y.Z` exists builds another index, which `finalize-images` refuses
unless its bytes are identical, and `npm` likewise refuses a tarball whose integrity is not the one
npm holds for the version: the version is spent, so cut a new one. Once the digests or the manifest have
expired, do not rebuild a manifest from tags; cut a new version. Manual writes to `:X.Y.Z` or to
npm's dist-tags are outside these checks. Staging tags are not cleaned up yet.

**An integrity mismatch.** `npm` fails with `INCIDENT` when the registry serves another integrity
than the tarball this run packed. npm's `latest` may already name that version. Check the dist-tag;
restore the previous version to `latest` only if the incident version still holds it; deprecate the
incident version; cut a new one. Never republish or unpublish.

**What stays unproven until a watched stable release.** The jobs above are tested against stand-in
`docker` commands, a stub GitHub API and a stub npm registry (`scripts/release-publication.test.mjs`,
`scripts/release-manifest.test.mjs`, `scripts/release-npm.test.mjs`). A real release is the first
run of the push by digest and the staging index on GHCR, the anonymous pull of staged digests, the
`ci` check against GitHub's API with the job's token, the finalize write, the lock's queueing in this
repository, the floor against the real registry, and the trusted (OIDC) publish of a downloaded
tarball. A dry run proves the archive path and the packing, not any of these.
