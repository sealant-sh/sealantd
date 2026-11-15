---
"@sealant/runtime-protocol": patch
---

A worktree no longer stops saving after a daemon restart that came right after a capture was
registered. When the daemon died after the registrar accepted a capture and before it removed that
capture from its staging queue, the first snap after the restart could replace that capture in the
queue. Every later register was then refused with a wrong-parent conflict, so nothing on that
worktree saved again, and a second restart laid the registered head over the disk, losing the edits
staged since. The restart now removes from the queue a capture the registrar already holds, before
it snaps. The log says `a capture registered before the daemon stopped was still queued; acked`
when it does.
