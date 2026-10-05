---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

Two capture timing bugs, found while fixing flaky tests:

- A change signalled while a class loop was between reading its clock and going to sleep woke
  nobody, and the loop slept until the old due time: a watched class's reconcile interval, a
  minute for the small class and ten for the bulk class. An overflow at startup went unhandled
  that long. The loop now checks the state again under the lock it sleeps on.
- A flush beside a bulk upload waited for the ship worker to let go of the pass, and the worker,
  having yielded to it, took the pass straight back, over and over. On arm64 a suspend flush
  beside a 5 s bulk upload took 5 to 19 s, the worker giving way 8,575 times in one of them. The
  worker now waits until the flush holds the pass.
