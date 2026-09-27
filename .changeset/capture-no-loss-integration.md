---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

A register the control plane refuses is fixed, never dropped; a final flush names unreadable work;
`plan.get` says which manifest format the daemon reads.

`capture.register` may answer 422 `missing-objects` (an object the manifest names is not in the
store, the keys in `missing`) or `unrestorable` (a section's tree would not restore). The daemon
used to retry the same register forever, so the chain stopped and a final flush never completed.
It now uploads the objects it staged again and registers again; when a named key is one it did
not stage (a pack retention removed while the daemon's chunk index still pointed at it) or the
same capture is refused again, it rebuilds that capture from disk in its place — same position,
same parent, the named packs forgotten and read again — and folds the captures staged after it
into it. `capture.status` gains `register_refused`, `register_refused_n`, `register_missing`,
`register_refusals` and `repairing` (fields 20–24 of `CaptureStatusReport`).

A final flush that fails because it cannot read work reports `incomplete_reason` `unreadable`
(it said `snapshot-failed`). Every `plan.get` sends `manifest_format: 2`, the highest section
format the daemon reads, so a control plane can refuse it a head it could not restore and cap the
format it is told to write; a 409 `manifest-format` answer is read as that refusal. The worktree
metadata overlay names paths with the same key encoding as dir objects (one implementation, the
same bytes).
