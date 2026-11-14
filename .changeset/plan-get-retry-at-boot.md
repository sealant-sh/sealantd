---
"@sealant/runtime-protocol": patch
---

A capture-store boot asks `plan.get` again when the request may never have reached the registrar:
a connection closed, reset or refused, a name that did not resolve, a timeout, a 5xx. It waits
0.25 s, 0.5 s, 1 s, 2 s and then 4 s between attempts, and gives up when the next wait would take
it past 20 s from the first failed attempt; the error then names the attempts, the time spent and
the last error. Before, one dropped connection failed the session's start with
`capture plan.get failed: transport: io: unexpected end of file`. A refusal from the registrar
still fails the boot at once, and a `worktree-leased` answer waits as before.
