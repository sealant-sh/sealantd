---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Opening the capture no longer erases a `.git/info/exclude` that is not UTF-8 (review 12 #1).
The daemon's `/.sealantd/` rule is appended to the file's bytes, never to a decoded copy, the
file keeps its mode, and the update stays atomic. Only a missing file reads as empty; any other
read error leaves the file alone. Before, a valid exclude file with a legacy-encoded byte (for
example a Latin-1 comment) read as empty, and every user rule in it was replaced by the daemon's
one line before the first capture.
