---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Launcher-provided secret environment: `sealantd boot` accepts a new `SEALANT_SECRET_ENV_FILE`
input — a JSON object (`name → value`) read exactly once at boot. Its entries are injected into the
harness child environment explicitly (they bypass the daemon's secret-name scrub, override
same-named passthrough entries, and can never set the boot-owned `HOME`/`USER`/`LOGNAME`/`PATH`),
and every value seeds the I/O redactor regardless of its name, so a workspace can receive
`DATABASE_URL`, `STRIPE_API_KEY`, and friends without them ever riding container env, `docker
inspect`, or captured output in the clear. Names are grammar-checked and must not be
`SEALANT_`-prefixed; a malformed or unreadable file fails boot loudly (parity with dotfiles
archives). The launcher is expected to remove the file once the workspace reports ready — from then
on the values live only in daemon memory and child environments. The `configHash` fingerprint
logged at readiness now covers the sanitized configuration (env keys, never values).
