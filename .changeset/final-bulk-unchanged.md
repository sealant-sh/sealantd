---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

A final capture flush no longer walks a dependency tree that has not changed since the last bulk
snapshot read every file of it, when the watcher saw no change in the class since. That walk was
4.8 s of a 25 s Stop on a box whose tree had not changed.
