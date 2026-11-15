---
"@sealant/runtime-protocol": patch
---

A capture-store boot no longer fails when one `plan.get` hangs and then drops. Each boot
`plan.get` now has its own time limit (10 s, then 15 s, then 20 s for every later attempt) instead
of the channel's 60 s, and the boot always makes at least three attempts before its 20 s budget
can end the retries. When every call hangs, the boot gives up 45.75 s after the first attempt
began, with `capture plan.get failed after 3 attempts over 45.8 s: <last error>`. Before, one call
that hung for 30 s spent the whole budget and the session failed to start.

The boot's reads from the object store (the head manifest, packs, dir packs and plan sources) are
now asked again after a dropped connection, a reset, a timeout or a 5xx: four attempts at most,
0.25 s, 0.5 s and 1 s apart, each reading the whole object again from its first byte. A 403 or a
404 still fails at once. When every attempt fails, the error reads
`gave up after 4 attempts over <time> s: <last error>`.
