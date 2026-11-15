---
"@sealant/runtime-protocol": patch
---

Live `file.changed` events no longer miss files inside a directory created within a new directory.
When a tool ran `mkdir -p a/b` and the second directory appeared while the daemon was still adding
watches for the first, `a/b` was reported once but never watched, so later writes inside it raised
no event until the shutdown diff. The daemon now lists a new directory again after adding its
watches, until no new directory turns up.
