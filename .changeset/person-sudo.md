---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

A per-person executor (a root daemon whose capture source carries an owner map naming at least one
person, Mend's ADR 0016) no longer
sets no-new-privileges on the daemon: every person there has passwordless `sudo`, which
no-new-privileges breaks, so the executor is root by design, not a sandbox, and its persons hold
`CAP_FOWNER` (pnpm relinks bins). Every other executor keeps no-new-privileges, as before (plan §18,
amended). The posture is decided once (`BootConfig::no_new_privileges`) and read by boot's
preparation and the runtime alike. Boot logs the posture and the state it found, and
`runtime.getCapabilities` reports `noNewPrivileges` (optional: absent is unknown).
