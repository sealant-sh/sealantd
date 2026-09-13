---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

`capture.replan` joins the protobuf `Command` oneof and the generated TypeScript, answered by
`CaptureReplanned` (worktree, epoch, head, files and bytes written versus skipped, removed,
`unchanged`). A standby executor boots on the project base under a placeholder worktree; once
the control plane assigns it a worktree, `capture.replan` fetches the plan again, materializes
the chain head as a delta over the disk, takes the worktree id and lease epoch the plan names,
drops captures staged under the placeholder, and resumes the cadence — so a hot-pool standby
serves joins and pickups without a cold materialize. Idempotent when the plan names what the
executor already has. The daemon also sends its `platform` on `plan.get` and honours a
`"pending"` bulk answer (another platform's dependency tree is not restored).
