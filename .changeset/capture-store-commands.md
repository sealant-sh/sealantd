---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Capture-store control commands (ADR-0015): `capture.now { kind }`, `capture.flush`,
`capture.status` and `lease.epoch` join the protobuf `Command` oneof and the generated TypeScript,
so a control plane can force a whole-workspace capture ahead of the daemon's cadence, flush staged
captures before a planned stop, read the capture runtime's state, and rotate the lease epoch. The
daemon also boots from a `capture` workspace source (`SEALANT_WORKSPACE_SOURCE=capture`), which
materialises the worktree from the session channel onto local disk and ships captures back.
