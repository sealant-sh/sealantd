---
"@sealant/runtime-client": patch
"@sealant/runtime-protocol": patch
---

`@sealant/runtime-client` depends on the exact `@sealant/runtime-protocol` version it was published
with, not a caret range. The two are versioned together, and a caret on a prerelease
(`^0.20.0-next.7`) would accept any later prerelease of the protocol.
