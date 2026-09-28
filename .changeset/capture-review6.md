---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The sixth adversarial review's daemon findings (#1, #2, #7), and the executor side of cross-repo
decision 17.

- **No filter driver of the user's runs in a capture, whatever its name (#1).** The capture
  emptied every filter driver the configuration defines, but read the names lossily: a driver
  named `raw\xff` became `raw\u{fffd}`, and the user's `raw\xff` clean filter still ran after the
  final flush had stopped every writer. It left a process behind that wrote after the flush
  answered complete and sealed. The overrides are now the driver's bytes, and git is asked again
  under them: a driver left with a command or `required` on, or a configuration that cannot be
  read, fails the git before it runs (a final flush over it is `snapshot-failed`). A final flush
  also takes a census before it seals: a descendant of the daemon alive after the writers stopped
  is killed and the classes are snapped again; one found on the last of three rounds answers
  `incomplete_reason: "processes-remain"` with no seal.
- **A write through another name of a file is captured within the cadence (#2).** A write
  through a bulk-class name of a tracked file dirtied only the bulk class, and a write through a
  name outside the workspace dirtied nothing: the old bytes stayed the capture for any number of
  intervals. An event on one name of a multi-link file now dirties every class holding a name; a
  multi-link file with names in both classes, or names neither holds, is stat'ed on its class's
  maximum interval; and a watched class with nothing pending is snapped on its reconcile interval
  (`Cadence::reconcile` 60 s, `bulk_reconcile` 600 s), a snap that stages nothing when nothing
  changed.
- **The raw tree holds every file's bytes (#7).** An ignored `.gitattributes` still converts, but
  the raw tree was hashed only when an attribute file was among the index entries: a CRLF file
  under an ignored `*.txt text` was sealed and restored as LF. Every regular file is now hashed
  raw (cached by stat).
- **Where an answer stands (decision 17).** `CaptureStatusReport` gains fields 27–30: `launch`
  (the executor `plan.get` named), `boot_id` (random per daemon process), `boot_generation` (the
  daemon processes that opened this disk's staging directory, persisted before the first answer;
  0 when it could not be) and `observation` (strictly increasing within one boot over every answer
  and every seal, the answer computed under it). A final seal carries `boot_id`,
  `boot_generation` and `observation` too. Same `(epoch, launch, boot_id)`: order by
  `observation`; same `(epoch, launch)` with different boots and generations above 0: by
  `(boot_generation, observation)`; anything else is incomparable. Control planes order evidence
  by this, never by their wall clocks, and fail closed on incomparable or contradictory evidence.
- **A key the bucket already holds is uploaded (decision 19).** `upload.urls` answers such a key
  in `present` (Mend verified its bytes and mints no URL for it); the executor used to take a key
  without a URL as an error and never registered the capture. It now takes a `present` key, like
  a PUT answered 412 under `If-None-Match: *`, as already uploaded and goes on. A key answered in
  none of `urls`, `multipart` and `present` is still an error.
