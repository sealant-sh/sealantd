---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

A per-person executor (a boot whose capture source carries an owner map, Mend's ADR 0016) no longer
sets no-new-privileges on the daemon: every person there has passwordless `sudo`, which
no-new-privileges breaks, so the executor is root by design, not a sandbox, and its persons hold
`CAP_FOWNER` (pnpm relinks bins). Every other executor keeps no-new-privileges, as before (plan §18,
amended). Boot logs which posture it took, `RuntimeConfig.no_new_privileges` carries it to the
runtime, and `runtime.getCapabilities` reports `noNewPrivileges`.
