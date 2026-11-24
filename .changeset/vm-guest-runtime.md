---
"@sealant/runtime-protocol": minor
---

`sealantd --vm` runs the daemon as PID 1 of a workspace microVM (the `host-vm` runtime). It
mounts the guest's two disks: an overlay root over the read-only base disk, with the workspace,
`/home` and `/var/lib/docker` on the data disk directly, and adds `/dev/shm` and the
`/dev/fd`, `/dev/stdin`, `/dev/stdout` and `/dev/stderr` links. It opens one connection to the
runner on vsock port 1026 and keeps it for as long as it runs. The boot configuration comes in
on it, and a `{"version":1,"type":"shutdown"}` frame on it (or the power button) starts the
same graceful shutdown as `SIGTERM`. It serves the control protocol on vsock port 1024 to the
host (CID 2) only. On its way out it syncs the data disk, then on the same connection sends
`{"version":1,"type":"exit","exitCode":…,"synced":…}`. It waits for
`{"version":1,"type":"exitAck","accepted":true}` before it powers off. `synced` is true only when
the data disk's `syncfs` completed. The mode comes from `sealantd.mode=normal|recover` on the
kernel command line, or `--vm-mode`. A normal boot also configures `lo` and `eth0`, writes a
combined CA bundle (`/etc/ssl/certs/sealant-ca-bundle.pem`, exported as `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`) and fills a missing or empty `/etc/hosts`. It
also forwards `MEND_SESSION_ENDPOINT` on loopback to vsock port 1027 and starts the guest
`dockerd` when asked, plus `nix-daemon` on a Nix image. The final flush stops the guest
`dockerd`'s containers twice and stops `dockerd` only after the second time, so a workspace
running Docker still ends with a complete flush. The image's `PATH` is set on the daemon itself,
so the capture's `git` and the dotfiles' `chezmoi` are found. When the guest is idle, it drops
clean page cache and trims the data disk. A recovery boot runs on the clean, read-only base disk
with only the workspace and `/home`. It writes nothing to the base disk (session journals go to
`/run/sealant/session-journals`) and starts no `dockerd`, dotfiles, harness or session forwarder.

A recovery boot (`sealantd boot --recovery` as well as `--vm` in recover mode) now answers only
`runtime.health`, `runtime.getCapabilities`, `getRuntimeMetrics`, `listProcesses`,
`capture.status`, `lease.epoch`, `capture.flush` of kind `final` and `runtime.gracefulShutdown`.
Every other command, including a suspend flush, `runtime.kill` and `signalProcess`, is refused
with `policy-denied`.

`SEALANT_CAPTURE_DIAL` sends capture traffic through a local relay instead of TCP:
`unix:/run/sealant/capture.sock` on the `docker` runtime, or `vsock:2:1025` (the default
under `--vm`). Each request keeps its URL's path, query and `Host` header (`Host: garage:3900`),
so presigned object URLs still verify. Plain HTTP to the relay needs no
`SEALANT_CAPTURE_ALLOW_PLAINTEXT`. Unset, or `tcp`, capture traffic is dialled as before.
