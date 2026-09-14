---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Byte-quota refusals are terminal (daemon-only; the packages ride the release train). A 413, or a
409 whose `reason` is `byte-quota`, is now `RegistrarError::QuotaRefused` with the body's `limit`,
`used` and `requested` instead of a wrong parent (409) or a protocol error (413): the shipper drops
that queue entry with its staged bytes and every queued capture that descends from it, logs the
capture's `n`, class and the numbers, and marks the class `refused` in `capture.status` (a new
`refused` field, one `CaptureClass` per refused class). A refused bulk class takes no further snap
until the next epoch or `capture.replan`; the small class keeps snapping and shipping, and the
engine continues the chain from the refused capture's parent, forgetting the chunk locations of
packs that never went up. Before this, neither status dropped the entry, so the ship worker re-ran
the same refused call every 5 s for good (observed on the cluster: a 775 MB bulk capture uploaded
in full, then `register n=4: … http 413` on every tick). `upload.urls` also carries `sizes` for
every key of a batch, not only multipart-sized ones, so the registrar can price a whole batch
before it mints a URL.
