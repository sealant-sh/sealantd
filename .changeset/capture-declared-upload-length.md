---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Every PUT URL is minted for the length the PUT then sends (daemon-only; the packages ride the
release train). `UrlMinter::put_url` takes the object's size, so the single-key fallback mint — the
path for a key no batch minted — declares that object's real byte count instead of the `0` it sent
before, and the git pack index's upload is sized from `fs::metadata` with the error surfaced rather
than swallowed into a `0`. `upload.urls` already carried `sizes` for every key of a batch; these
were the two places a key could still travel with a size that was not its length.

Before this, a registrar that binds an upload signature to an exact content length — Mend's upload
length binding, `MEND_CAPTURE_REQUIRE_SIZES` — would mint a URL signed for zero bytes and the
store would refuse the body, or the declared size would simply be wrong. Both PUT paths already
sent `Content-Length`; now the length in the signature and the length on the wire are the same
number by construction.
