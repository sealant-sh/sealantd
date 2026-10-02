---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

A pack index's SHA-256 is declared on a multipart mint too, so a registrar that answers it as a
single PUT can bind that URL to its bytes (before, it went unbound and the seal waited for it).
