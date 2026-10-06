---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Capture applies the harness credential and machine-state tables under every person's saved
directory (`people/<account id>/` in the harness home, Mend's per-person layout) as it does at the
root, the sibling rule included: a login a link-breaking write leaves in a person's saved directory
is never captured, and a capture that holds one never restores it. The tables apply under every
shared conversation (`people/<id>/conversations/<session>/`) too, and a shared conversation never
saves `file-history/`: Claude Code's file history is never saved anywhere.

Codex's logs database (`codex-db/logs_*`) and every SQLite `-shm` file in `codex-db/` are machine
state, never saved; Codex's thread index and memory database are saved with their WAL. ADR-0015
lists both entries, and a new kind of entry, a pattern with one `*` in its last component.
