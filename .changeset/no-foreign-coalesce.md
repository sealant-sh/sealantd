---
"@sealant/runtime-protocol": patch
---

A session that claims a standby workspace no longer fails to save. When the standby had staged a
capture of its own before the claim (it holds no lease, so the capture waited to be sent again) and
the claim's re-plan landed while that capture was being sent, the session's first capture was
merged into it: it named the standby's capture as its parent and carried packs under the standby's
key prefix, so the registrar refused it and the final flush never finished (`not saved · workspace
kept`). A capture staged under another identity is now never merged into the session's, and it is
dropped once the shipper lets go of it. Removing a capture from the queue now checks that it is the
capture the shipper sent, so the session's capture, which takes the same chain position, is never
removed in its place. The log says `a capture staged under another identity is not coalesced with`
and `a capture staged under another identity was dropped once the shipper let go of it`.
