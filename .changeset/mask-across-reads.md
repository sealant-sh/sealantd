---
"@sealant/runtime-protocol": patch
---

A secret sealantd masks in recorded output stays masked however the process's writes split it.
Before, sealantd masked each read on its own, so a workspace secret written in two parts reached
the session journal, the event spool and `io.chunk` events as two raw halves. Each recorded stream
(exec stdout and stderr, a session's output, pipe stderr and input) now holds back a short suffix
that could still begin a secret until a later read, or the stream's end, decides it. Overlapping
matches are masked as one span, and a PTY session also masks a multi-line secret written with CRLF
line ends.

An `io.chunk`'s `streamOffset` is now the raw position of the bytes it stands for, and its
`transform.originalByteCount` the number of those raw bytes; `byteCount` stays the recorded
length. A chunk can stand for raw bytes and record none, when a masked span from the chunk before
covers them all. Session input chunks carry offsets too, where they were all 0. A held suffix is
recorded before the stream's `process.exited`; when reading stops before the writer closed (a
drain cut short after the leader exits), a held suffix that could begin a secret is masked. A
session refuses input once its leader has exited and its output has drained, and a write the
leader's exit leaves blocked fails instead of waiting.
