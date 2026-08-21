---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Pipe-mode sessions: `openSession` accepts `mode: SESSION_MODE_PIPE` to start the leader with plain
stdio pipes and no controlling terminal — for processes that speak a byte protocol over stdio
(JSON-RPC / NDJSON servers). stdout is the journaled, attachable output with the same reattach and
tombstone semantics as PTY sessions; stderr is recorded as telemetry only; `writeStdin` feeds stdin;
`resizePty` is rejected. `SessionSummary.mode` reports the shape and `FeatureMatrix.pipeSessions`
advertises support. Unspecified `mode` still means PTY.
