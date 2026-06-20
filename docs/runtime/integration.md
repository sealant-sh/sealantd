# Consuming sealantd from the monorepo

sealantd ships **two artifacts** that the `get-sealant/sealant` monorepo consumes through different
channels — the daemon **binary** runs inside each sandbox container; the **TypeScript SDK** runs in
the orchestrator that drives sandboxes over the control socket.

## 1. The daemon binary → multi-arch image (GHCR)

A `vX.Y.Z` tag triggers `.github/workflows/release.yml`, which builds and pushes a static,
multi-arch image to `ghcr.io/get-sealant/sealantd`. The runtime layer is `scratch` + one static
binary.

Bake it into the sandbox image with a single `COPY --from` — buildx selects the matching arch
automatically for each target platform:

```dockerfile
# in the sandbox image the buildkit builder assembles
COPY --from=ghcr.io/get-sealant/sealantd:X.Y.Z /usr/local/bin/sealantd /usr/local/bin/sealantd
```

Pin by version (or by `@sha256:` digest for full reproducibility). Launch it in the sandbox with a
socket on a shared path, e.g.:

```sh
sealantd --socket /run/sealantd.sock --workspace /workspace --watch-filesystem --network-proxy
```

Run it as the **same uid** as the controlling process so peer-credential validation passes
(`SO_PEERCRED`; the socket is also `0600`).

### Without a registry (alternative)

`scripts/build-release.sh` emits `dist/sealantd-{amd64,arm64}`; attach them to a GitHub Release and
`curl` the right arch in the sandbox Dockerfile. Simpler infra, but you own arch selection +
checksum verification.

## 2. The TypeScript SDK → npm

`@sealant/runtime-protocol` (wire codec + types) and `@sealant/runtime-client` (the `SealantClient`)
are published to npm from the same tag. Versioning: the npm **major** tracks the wire
`schemaVersion`, so a breaking wire change is loud at the dependency level.

```sh
pnpm add @sealant/runtime-client
```

```ts
import { SealantClient } from "@sealant/runtime-client";
const client = await SealantClient.connect("/run/sealantd.sock");
```

> Status: the typed SDK (Buf-generated types + Effect-Schema surface) is in progress; until it
> publishes, see `packages/` and `docs/runtime/operations.md` for the current shape.

## Version discipline

One git tag drives both artifacts (image tag + npm version) so a deployment pins a single,
consistent `(binary, SDK)` pair.
