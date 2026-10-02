---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

A final capture flush uses every core. Measured on a 140,548-file, 2.3 GB dependency tree: 28.9 s
before, 2.9 s now on a Ryzen 9950X3D, and 69 s before, 6.3 s now on an i9-9900K.

- Small files are read, hashed and compressed on reader threads, in the order the build takes them.
- A file too large to read ahead whole is still read in order, and its parts are hashed and
  compressed on those threads. 24 such files were 923 MB of that tree.
- A pack's digest is computed on a thread of its own, and the pack is synced and named while the
  next one is written.
- SHA-256 comes from `ring`, about twice as fast as before on a CPU without SHA extensions.
- Objects of 16 MiB and more upload four at a time. They went up one at a time.
- A single PUT may run for as long as its size needs at 512 KiB/s. It was cut at 10 minutes.

The output is the same bytes: the same chunks, packs and tree as a build on one thread.
