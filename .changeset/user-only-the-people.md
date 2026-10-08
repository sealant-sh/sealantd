---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

sealantd runs a process only as one of the executor's people. When `exec`, `openSession` or
`dotfiles.apply` names a `user`, the daemon checks the passwd entry it resolves: the uid must be in
Mend's reserved range (40001-49999) with primary group 40000, or, under an owner map
(`SEALANT_CAPTURE_OWNER_MAP`), one of the map's `people` or its `worktree` uid in the map's `gid`.
The range applies under a map too, because the map is read only at boot and a person who joins the
worktree later is not on it. Anyone else is refused with `invalid-argument` before anything
starts, and the message says why (`uid 1500 is not one of this executor's people (owner map) and
is outside the range of Mend's people (40001-49999)`). Root and root's group stay refused. A
caller's own check is not enough here, since a person with `sudo` in the executor can edit
`/etc/passwd`. Requests that name no user are unchanged.
