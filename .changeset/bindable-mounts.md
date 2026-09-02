---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

`bindMount { mountPath, subpath }` (ADR-0014): point a bindable mount's path at a subdirectory of
its root, or unbind with an empty subpath. Boot reads `SEALANT_BINDABLE_MOUNTS` and `SEALANT_BINDS`,
and `SEALANT_WORKSPACE_SOURCE=standby` makes the working directory itself bindable. The client gains
`bindMount(mountPath, subpath)`.
