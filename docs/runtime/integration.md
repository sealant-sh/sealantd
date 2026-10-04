# Consuming sealantd from the monorepo

sealantd ships **two artifacts** that the `sealant-sh/sealant` monorepo consumes through different
channels — the daemon **binary** runs inside each workspace container; the **TypeScript SDK** runs in
the orchestrator that drives workspaces over the control socket.

## 1. The daemon binary → multi-arch image (GHCR)

A `vX.Y.Z` tag triggers `.github/workflows/release.yml`, which builds and pushes a static,
multi-arch image to `ghcr.io/sealant-sh/sealantd`. The runtime layer is `scratch` + one static
binary.

Bake it into the workspace image with a single `COPY --from` — buildx selects the matching arch
automatically for each target platform:

```dockerfile
# in the workspace image the buildkit builder assembles
COPY --from=ghcr.io/sealant-sh/sealantd:X.Y.Z /usr/local/bin/sealantd /usr/local/bin/sealantd
```

Pin by version (or by `@sha256:` digest for full reproducibility). Launch it in the workspace with a
socket on a shared path, e.g.:

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
publish to npm from the same tag (the `npm` job in `release.yml`, which syncs the package version to
the tag and publishes with provenance). Versioning: the npm **major** tracks the wire
`schemaVersion`, so a breaking wire change is loud at the dependency level. Requires an `NPM_TOKEN`
repo secret.

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

- `ghcr.io/sealant-sh/sealantd-next:0.20.0-next.N`, amd64 and arm64.
- `@sealant/runtime-protocol-next` and `@sealant/runtime-client-next` `0.20.0-next.N` on npm's
  `next` dist-tag; the client depends on the protocol through an exact alias,
  `"@sealant/runtime-protocol": "npm:@sealant/runtime-protocol-next@<version>"`.

The `next` trusted publisher is registered only on the two `-next` packages, so nothing in that
workflow can publish `@sealant/runtime-*` or write `ghcr.io/sealant-sh/sealantd` tags. Only
`publish` holds the credential; it installs nothing, runs no repository code, refuses an artifact
holding anything but the expected tarballs, runs npm from an empty directory, and publishes a
tarball it rebuilt from npm's own reading with an allowlisted manifest.

Core pins a prerelease by exact version when it needs a daemon change before sealantd releases:
`ghcr.io/sealant-sh/sealantd-next:<version>` and the runtime packages as exact aliases
(`"@sealant/runtime-client": "npm:@sealant/runtime-client-next@<version>"`). Core's recovery check
treats a `sealantd-next:X.Y.Z-next.N` image of a version after 0.19.0 like a release.

To release: merge the Version Packages pull request and **freeze main until the tag**; Core pins
that commit's next build; then tag that same commit. Core refuses to cut a stable release while it
pins a prerelease, so this tag comes first. The whole order is in sealant-sh/mend
`docs/operations/next-channel.md`. The release refuses while an npm prerelease of the version came
from a commit the tag leaves out, which is what a merge during the freeze produces.
