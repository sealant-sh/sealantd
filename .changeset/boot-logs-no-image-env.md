---
"@sealant/runtime-protocol": patch
---

Two log lines no longer print values that can hold a credential. The VM runner's `boot config loaded` line names the image's `Env` variables without their values and gives the image entrypoint and command as argument counts, and a refused container stop during final capture logs the Docker daemon's status without its response body.
