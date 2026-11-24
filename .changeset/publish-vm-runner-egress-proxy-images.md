---
"@sealant/runtime-protocol": patch
---

Every release now publishes two more images beside `ghcr.io/sealant-sh/sealantd`, each for amd64 and arm64 at the same version: `ghcr.io/sealant-sh/vm-runner` (the `host-vm` runner, with Cloud Hypervisor and the guest kernel) and `ghcr.io/sealant-sh/egress-proxy` (the per-workspace egress proxy). Each `-next` build publishes them as `vm-runner-next` and `egress-proxy-next`. The npm packages publish only once all three images are tagged, and the run summary lists each image as `tag@sha256:…` to pin.
