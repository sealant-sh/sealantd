---
"@sealant/runtime-protocol": patch
---

When `nft` refuses the VM runner's ruleset (in setup or `--self-test`) and exits before reading all of it, the runner now reports nft's own reason, such as `Operation not permitted`, not a `Broken pipe` from writing the ruleset.
