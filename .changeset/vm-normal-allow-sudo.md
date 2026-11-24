---
"@sealant/runtime-protocol": patch
---

`sudo` now works inside a `host-vm` workspace. A normal `sealantd --vm` boot leaves no-new-privileges unset, whatever the workspace source (clone, SDK capture or a per-person capture), because the guest kernel is the isolation boundary. Before, a workspace with no per-person owner map inherited the container posture, and `sudo` failed with `effective uid is not 0, is /usr/bin/sudo on a file system with the 'nosuid' option set`. A recovery boot still sets no-new-privileges, owner map or not, and container boots (`sealantd boot`) keep the posture they had. The boot log names a microVM's posture as `privilege posture: microVM normal boot: …`.
