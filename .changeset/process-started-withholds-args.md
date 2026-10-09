---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

`process.started` never carries a process's arguments. They can carry secrets (a token a script
writes, a file's bytes in base64), and the daemon published them as text to every event subscriber
and to the durable spool on disk (`--spool-dir` / `SEALANT_SPOOL_DIR`). The event now names the
executable and carries `argCount` and `argLengths` (each argument's length in UTF-8 bytes, in
order), the shape Sealant Core already stores; `args` stays in the schema for wire compatibility and
is always empty.

Exec and session open build the event without the text, and the event bus withholds any text a
publisher passes before a subscriber or the spool sees it. On start, a daemon rewrites spool
segments an older daemon left with argument text (each segment to a synced copy renamed over the
original) before it replays them, and withholds the text from every replayed event even if the
rewrite fails.
