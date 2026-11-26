---
"@sealant/runtime-protocol": patch
---

The daemon's spans now read in Sentry as what they are, instead of every one showing as `default` with a blank description. Control requests are RPC server calls (`rpc.server`, `sealantd.control/<method>`); process and session spawns, journals and attaches are `subprocess.*` and `file.create` spans; egress proxy policy changes are HTTP server routes (`PUT /v1/policy`); boots are `sealantd.boot` with a `sealantd.boot.stage` per stage, and a microVM launch is `sealantd.vm`. Each span also carries the release and environment the daemon reports, and `sealant.runtime_id` (plus `sealant.workspace_id` when the launcher names one), so Sentry can filter by them. A failed process or session spawn marks its span failed. A refused request's code is recorded in its wire form (`process-not-found`) as `sealantd.error_code` and `rpc.response.status_code`.
