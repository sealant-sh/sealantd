---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Keep platform-injected harness credentials in the harness environment. The boot passthrough scrub
dropped every env var that looked like a secret — including `CLAUDE_CODE_OAUTH_TOKEN`, `GITHUB_TOKEN`,
and `GH_TOKEN`, which the control plane injects into the container precisely so the harness can use
them. Those contract keys now survive the scrub, and injectors can exempt further keys by declaring
them in `SEALANT_HARNESS_ENV_KEYS` (comma-separated). Consumed `SEALANT_*` keys can never be exempted.
