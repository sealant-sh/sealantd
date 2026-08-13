---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

End interactive terminal attachments when their session leader exits, even if a helper process
inherited the PTY slave and keeps it open. Sealantd now drains output already written by the leader,
emits the final stream end immediately, and releases the PTY master instead of making clients wait
for unrelated helper cleanup.
