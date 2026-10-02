---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Upload URLs bound to their bytes. The executor lists `sha256` in `plan.get`'s `upload_answers`: it
sends `x-amz-checksum-sha256` (the SHA-256 of the bytes, base64) on every PUT whose URL signs it,
and declares in `upload.urls` the SHA-256 of each pack index, the one key whose name does not say
it. A registrar on a store that cannot refuse an overwrite but checks a signed checksum (Garage) can
then mint URLs that write those bytes or nothing: no write authority, and no seal waits for them to
expire. An older registrar ignores both, and nothing changes for a URL that does not sign it.
