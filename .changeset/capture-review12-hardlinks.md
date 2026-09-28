---
"@sealant/runtime-protocol": patch
"@sealant/runtime-client": patch
---

A cold restore gives back every hardlink group across classes as one inode (review 12 #2). A
link the worktree metadata makes (`shared`, `cross_links`) now moves every name of the linked
member's own restored hardlink group. The bulk index holds one name per group, so those links
name only that one. Before, pnpm's peer-context copies of a local package (two bulk names of a
tracked file's inode, made by a plain `pnpm install`) came back with one copy on an inode of its
own, and an edit to the restored package reached only one consumer. The same applied to a
workspace file with several bulk names. A sealed final capture restored whole now also checks,
once every link is made, that each set of names the capture joins is one inode per filesystem,
and fails the materialize (`LinkUnfulfilled`) if it is not.
