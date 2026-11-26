---
"@sealant/runtime-protocol": patch
---

sealantd no longer sends a trace of its own for a health check, capabilities probe, metrics or capture status read, lease check or shutdown that arrives without a caller's trace, or for the egress proxy's heartbeat. With a caller's trace, each is still a span in it. A boot's setup steps and harness spawn now show inside the boot's trace instead of as separate `sealantd.process.spawn` traces, and other background work no caller or boot started sends no trace.
