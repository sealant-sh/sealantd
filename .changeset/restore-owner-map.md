---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

A capture restore takes an owner map (`SEALANT_CAPTURE_OWNER_MAP`, Mend's per-person layout):
each person's saved directory (`people/<account id>/` in the harness home) is restored owned by
their uid and the shared group, the directory itself 0710 and the rest at its recorded mode. The
worktree, its git directory and the shared conversations (`people/<id>/conversations/`) get the
owner's read, write and execute bits copied to the group (a 0600 file comes back 0660) and setgid
on directories, in the `chmod` the restore already makes, so a capture root made with 0644/0755 comes
back editable by every person at no extra syscalls. At boot the worktree root goes to the change's
owner and the group, and the group's default ACL is set on it and on `/opt` and `/var/cache`.
Captures still record no owner; without a map nothing changes.

`Capabilities` gains `supports`, the names of what the daemon can do beyond the schema; this
daemon names `restore.owner_map`.
