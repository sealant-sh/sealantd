---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

sealantd runs a process only as one of the executor's people. When `exec`, `openSession` or
`dotfiles.apply` names a `user`, the daemon checks the passwd entry it resolves: with an owner map
(`SEALANT_CAPTURE_OWNER_MAP`), the uid must be one of the map's `people` or its `worktree` uid and
the primary group the map's `gid`; without one, the uid must be in Mend's reserved range
(40001-49999) and the primary group 40000. Anyone else is refused with `invalid-argument` before
anything starts, and the message says why (`uid 1000 is not one of this executor's people (owner
map)`). Root and root's group stay refused. A caller's own check is not enough here, since a
person with `sudo` in the executor can edit `/etc/passwd`. Requests that name no user are
unchanged.
