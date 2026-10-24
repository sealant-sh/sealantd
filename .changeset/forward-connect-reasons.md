---
"@sealant/runtime-protocol": minor
---

A TCP forward that cannot connect says why. Its `internal-error` keeps its code and message and
gains `detail.reason`: `connection-refused` (nothing listens on that address and port),
`name-unresolved` (the host did not resolve, or not in time), `network-unreachable`, or
`dial-timeout`. A failure outside those kinds carries no reason. The reason comes from where and
how the connect failed, never from the error's text, and across a host's addresses it is the most
telling one: a refusal, then a timeout, then unreachable. The package exports the reasons as
`FORWARD_CONNECT_REASONS` and the `ForwardConnectReason` type, so a caller imports them rather than
retyping them.

A connect, name resolution included, gives up after 5 seconds instead of the kernel's own timeout.
A host's addresses are tried in turn, each starting 250 ms after the one before or as soon as it
fails, so one that does not answer leaves time for the others. sealantd runs a forward's open
beside the connection's reader, so a slow dial no longer holds up the connection's other requests
and channels, and closing the connection drops the dial and its socket at once.
