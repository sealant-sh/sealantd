---
"@sealant/runtime-protocol": patch
---

A secret sealantd masks in recorded output stays masked however the process's writes split it.
Before, sealantd masked each read on its own, so a workspace secret written in two parts reached
the session journal, the event spool and `io.chunk` events as two raw halves. Each recorded stream
(exec stdout and stderr, a session's output, pipe stderr and input) now holds back a short suffix
that could still begin a configured secret until a later read, or the stream's end, decides it.
Overlapping matches are masked as one span. A PTY session also masks a multi-line secret its
output writes with CRLF line ends, and one its input sends with CR.

The token shapes (`ghp_…`, `sk-…`, `AKIA…`) hold nothing until a token's whole prefix has been
seen, so a live terminal shows every keystroke and frame at once; a token's bytes after its
prefix wait until it is long enough to mask or ends. The prefix stays in the record:
`ghp_***REDACTED***` where it was `***REDACTED***`.

An `io.chunk`'s `streamOffset` is now the raw position of the bytes it stands for, and its
`transform.originalByteCount` the number of those raw bytes; `byteCount` stays the recorded
length. A chunk can stand for raw bytes and record none, when a masked span from the chunk before
covers them all. Session input chunks carry offsets too, where they were all 0. Every stream's
held suffix is recorded before the `process.exited` that ends it, pipe-session stderr included:
stderr now drains after the leader's exit within the same bounds as stdout. When reading stops
before the writer closed (a drain cut short after the leader exits), or input is cut off (the
leader exits, or a write fails part way), a held suffix that could begin a secret is masked.
Input is recorded part by part as the leader takes it. A session refuses input once its leader
has exited, and a write the exit leaves blocked fails instead of waiting.
