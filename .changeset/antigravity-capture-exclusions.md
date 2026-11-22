---
"@sealant/runtime-protocol": patch
---

Capture and restore now exclude Antigravity (`agy`) credentials (`.gemini/antigravity-cli/antigravity-oauth-token`, `.gemini/antigravity-acp/antigravity-oauth-token`, `.gemini/config/mcp_config.json`, logs and crash dumps) and machine-local state (`builtin/`, `updater/`, `presence/`, `installation_id`, `last_check.timestamp`, `cli.log`, `.cache/antigravity/`, and SQLite `*-shm` files), while preserving conversation databases, WALs, brain artifacts and settings across stop and resume.
