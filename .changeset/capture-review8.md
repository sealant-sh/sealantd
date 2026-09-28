---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The eighth adversarial review's daemon findings (#1, #2, #3, #10) and the executor side of
cross-repo decisions 22 and 23.

- **A root reached through a symlink is read through it (#1).** A `.git` moved beside the
  worktree and linked back, or a harness home configured as a link, was listed as nothing: its
  bookkeeping (`config`, `MERGE_MSG`) or transcript was missing from a sealed restore. Roots are
  now walked through the link (the link text rides `workspace.root_links`), and a root that is
  not a directory at all makes a final flush `unreadable` instead of an empty listing.
- **A symlinked `FETCH_HEAD` or operation document keeps what it names (#2).** The collector read
  regular files only; it now reads through the link as git does, and one it cannot read makes a
  final flush `snapshot-failed`.
- **A symlink with several names makes a final flush incomplete (#3, decision 23).** No class
  carries one inode for a symlink's names; a final flush over one fails naming it instead of
  sealing two separate symlinks.
- **SHA-256 repositories (#10).** The git section names a format that is not SHA-1
  (`object_format`, a new manifest feature) and the restore initializes its repository with it
  before any pack goes in. A store that does not read `object_format` gets no complete final flush
  of a SHA-256 repository.
- **Complete only on a recorded seal (decision 22).** `capture.register` answers
  `seal: {state: "recorded" | "withheld" | "refused", reason?}` for a capture carrying
  `final_seal` (on a lost ack too). A final flush is complete only on `recorded`; `withheld` is
  asked again by re-sending the same register (bounded), and still withheld, refused or not said
  answers `sealing`.
