---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Custom-base support: `sealantd boot` accepts `SEALANT_OS_FAMILY=custom` (tool paths fall back to
`/bin/sh` — the custom-base contract guarantees a POSIX shell and nothing more), and the sealantd
image now ships a fully static `socat` at `/usr/local/bin/socat` beside the daemon, so workspace
image builders can `COPY --from` the control-relay dependency into any base instead of depending
on the base's package manager.
