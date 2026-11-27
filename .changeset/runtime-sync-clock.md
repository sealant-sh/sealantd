---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Add `runtime.syncClock` control command so `sealant-vm-runner` can step a microVM guest's wall clock back to host UTC after host sleep/wake.
