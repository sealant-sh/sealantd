---
"@sealant/runtime-protocol": minor
---

`sealantd --vm` runs the daemon as PID 1 of a workspace microVM (the `host-vm` runtime). It
mounts the guest's two disks: an overlay root over the read-only base disk, with the workspace,
`/home` and `/var/lib/docker` on the data disk directly. It reads its boot configuration from
the runner on vsock port 1026 and serves the control protocol on vsock port 1024 to the host
(CID 2) only. On its way out it syncs the data disk, reports its exit code on port 1026 and
powers off. The mode comes from `sealantd.mode=normal|recover` on the kernel command line, or
`--vm-mode`. A normal boot also configures `lo` and `eth0`, writes a combined CA bundle
(`/etc/ssl/certs/sealant-ca-bundle.pem`, exported as `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and
`NODE_EXTRA_CA_CERTS`), forwards `MEND_SESSION_ENDPOINT` on loopback to vsock port 1027 and
starts the guest `dockerd` when asked. When the guest is idle, it drops clean page cache and
trims the data disk. A recovery boot runs on the clean base disk with only the workspace and
`/home`, and starts no `dockerd`, dotfiles, harness or session forwarder.

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
