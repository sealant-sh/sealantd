---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Capture leaves pi's and opencode's own login files out of the harness home, as it does Claude
Code's and Codex's: `.pi/agent/auth.json` and `.local/share/opencode/auth.json`. A login made inside
a session with either harness is never captured; their settings and sessions still are.
