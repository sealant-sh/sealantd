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
