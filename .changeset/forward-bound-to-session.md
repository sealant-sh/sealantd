---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

A forward can be bound to a session. `openForward` and `openForwardConnection` take
`ownerSessionId` (`OpenForwardArgs.owner_session_id`, field 6): the forward opens only once the
session's processes, and no other process, hold the far end of the connection sealantd made, and
its result echoes the session in `boundSessionId` (`ForwardOpened.bound_session_id`, field 2).

A holder belongs to the session when it shares the leader's Linux session id, or when it runs as
the leader's user and group and the first `SEALANT_SESSION_MARKER` entry of its environment is the
session's marker. The marker is a secret sealantd mints per session, never the session id. Every
session leader carries it, and so does an `exec` that names a running session and runs as that
session's user and group; any other `exec` has the variable removed. A server that called
`setsid` or double-forked still counts this way. sealantd reads each process through one handle on
its `/proc/<pid>` directory, so a reused pid reads as gone, and reads another user's fds and
environment with that user's filesystem ids, so it needs no `CAP_SYS_PTRACE`. The whole check,
scans included, runs off the async runtime within the dial's 5 s deadline. No byte crosses before
the check passes. A bound forward ends when the session's leader exits, as soon as the leader is
reaped, with one `End` whose error is `owner-exited`.

A refusal carries `detail.reason`, which the package exports as `FORWARD_BINDING_REFUSALS`:
`owner-exited` (`session-not-found`: the session is not running), `peer-mismatch`
(`policy-denied`: a process outside the session holds the connection), or `binding-unverifiable`
(`policy-denied`: no holder could be found and checked in time, such as a server that never
accepts, or a holder whose membership could not be read). A bound forward is TCP to a loopback
address only (`invalid-argument` otherwise, checked before the session is looked up). `supports`
names `forward.owner`; a daemon without it ignores the field and opens the forward unbound, so a
caller checks the echo.

What the binding does not prove: a process of the session's own user can copy the marker into its
environment, a long-lived server the session started (a `tmux` server) passes the marker to what
it starts later from any session, and a holder of another uid than the listener's is not looked
for. A process whose fds cannot be read, such as a non-dumpable `ssh-agent`, does not stop a
member's holding from proving the binding. A cgroup per session would prove membership without
the marker; that is a follow-up.
