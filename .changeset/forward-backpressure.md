---
"@sealant/runtime-client": minor
"@sealant/runtime-protocol": minor
---

A forward can hold back what it reads instead of buffering it without bound.
`openForwardConnection(stream, { host, port, protocol, executionId?, highWaterMarkBytes })` opens
one forward on a connection that carries nothing else, and owns that connection from then on:

- It pauses reading the connection while the forward holds more than `highWaterMarkBytes` unread
  bytes, and resumes once the consumer reads them back under. sealantd then stops reading the
  forward's target, so a slow consumer holds back a fast producer. Each payload it holds is its own
  copy, so the bytes held are the bytes counted.
- `channel.destroy()` closes the connection, also while it is paused, and sealantd reaps the
  forward when the connection closes. The target's `End` ends the connection once queued writes
  have flushed.
- It rejects when the forward does not open, when the connection closes first, or when more than
  the mark arrives before sealantd confirms the forward. It never resolves with a channel that
  lost bytes.
- The mark must be a positive integer; anything else is a `RangeError` before the connection is
  touched.

`OpenForwardArgs.dedicated` (field 5) tells sealantd that the connection carries only this forward,
so it sends that connection no events. `openForwardConnection` sets it. A daemon that predates the
field keeps sending events, which the connection drops.

`Channel.write()` returns the connection's `write()` result (`false` once its outbound buffer is
full), and `Channel.drained()` resolves when that buffer drains. `drained()` rejects once the
connection can take no more writes: after a write error, a close, or `close()`. `Channel.destroy()`
also drops inbound bytes still queued on a channel the daemon already closed. The multiplexed
`SealantClient` keeps reading as before.

Breaking: `SealantClient.openForward` takes one object, `{ host, port, protocol, executionId? }`,
in place of positional arguments. `ChannelTransport` gains `drained` and `inboundQueued`, and its
`sendData` returns the `write()` result.
