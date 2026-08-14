---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

`sealantd boot` accepts `SEALANT_OS_FAMILY=ubuntu` (Ubuntu workspace images boot with
fedora/arch-style tool-path defaults; the glibc loader shim stays Nix-only). The unknown-value
error now lists `fedora|arch|nix|ubuntu`.
