---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

The released daemon image ships `sealantctl` beside `sealantd` and `socat` (image-only; the
packages ride the release train). A Lambda MicroVM's in-VM agent runs `sealantctl capture flush`
in the platform's suspend and terminate hooks, where no control plane is connected to ask the
daemon for it. An image builder can now `COPY --from` the client out of the released image, as it
does the daemon. Before this the image held no `sealantctl`, so a workspace image built from a
released daemon could not flush its captures when its MicroVM was stopped.
