---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

A delta restore keeps no hardlink the capture does not hold (review 15 #2). A standby's
`capture.replan` reuses a file whose bytes it already has, and the file kept every name its
inode had on the standby's disk. After a standby's `pnpm install` linked a tracked package file
into `node_modules`, a head whose source had since replaced that file with its own copy came
back still linked: an edit to the tracked file reached the installed package, and restoring the
tracked file's mtime changed the package's. Two tracked aliases split after a restore stayed one
inode the same way. A whole restore now puts each group of names the capture joins, a single
name included, on an inode of its own before it links anything: only multiply-linked files are
checked, and only the names that must leave an inode are copied (same bytes, mode and mtime). A
sealed final capture restored whole also fails the materialize if any inode still holds names
of two groups.
