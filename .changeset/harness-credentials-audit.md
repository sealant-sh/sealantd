---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Capture leaves every harness credential out of the harness home, after an audit of Claude Code
2.1.289, Codex 0.160.0, opencode 1.18.34 and pi 1.0.2 in a workspace-like container with no OS
keyring. Newly left out, and never restored from an earlier capture:

- Codex: `.codex/.credentials.json`, where Codex keeps MCP server OAuth tokens when no keyring is
  available (every workspace), `.codex/shell_snapshots/` (every exported environment variable with
  its value, present while a session runs and left behind when it is killed), and `.codex/secrets/`.
- Claude Code: `.claude/.device-keys.json`, and the directories `.claude/backups/` (copies of
  `~/.claude.json`, with a Console API key and MCP server headers), `.claude/shell-snapshots/`,
  `.claude/session-env/` and `.claude/ide/`.
- pi: `.pi/agent/mcp-auth.json` (pi's own MCP server OAuth tokens), `.pi/agent/oauth.json`, `.pi/agent/mcp-oauth/` and `.pi/agent/mcp-oauth-encrypted/`,
  `.pi/agent/mcp.json`, and the copy Mend delivers from a person's pi profile
  (`.pi/agent/mend/profile/root/mcp.json`, `.mend/pi-profile-kept/`).

A login or token one person made in a session no longer reaches the next session in the worktree.
The list can now name a directory as well as a file, and a file covers its suffixed siblings (a
lock, a write's temporary, a backup copy). ADR-0015 lists every entry.
