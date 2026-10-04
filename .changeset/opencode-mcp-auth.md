---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Capture leaves opencode's MCP server logins out of the harness home:
`.local/share/opencode/mcp-auth.json` (the OAuth tokens and client secrets of the MCP servers
opencode signs in to), as it does opencode's own `auth.json`. A sign-in made inside one person's
session is no longer saved, and no longer reaches the next session in the worktree, anyone's.

A restore never writes a harness credential file back either: a capture made before a file joined
the list (opencode's `mcp-auth.json` until now) still holds it, and materialize now skips every
harness credential under the harness home instead of restoring it.
