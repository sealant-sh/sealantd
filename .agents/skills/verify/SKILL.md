---
name: verify
description: Run a real sealantd, drive it with sealantctl, and keep the event stream as evidence. Use to prove a sealantd change works beyond its tests, before opening or merging its PR.
---

# Verify a sealantd change

Prove the change by running the real daemon and reading what it records. A green test suite says the
code does what the tests ask; this says the daemon does what the change claims.

## 1. Say what you expect to see

Before running anything, write down the events or output the change should produce, and what you
would see if it were broken. For example: "a secret written in two parts appears masked in both
`io.chunk` events". This is the claim the run checks.

## 2. Start with the demo

`examples/demo.sh` builds `sealantd` and `sealantctl`, starts a daemon on a temporary socket with
filesystem watching and the network proxy on, then runs `health`, `capabilities`, an `exec` that
writes and prints a file, and a graceful `shutdown`. Each `sealantctl` call prints JSON events.

On Linux, run it directly. On a Mac, run it in a Linux container:

```sh
docker run --rm -v "$PWD":/src -w /src \
  -v sealantd-cargo-registry:/usr/local/cargo/registry \
  -v sealantd-linux-target:/src/target \
  rust:1.100.0-slim examples/demo.sh
```

The first run compiles the workspace and takes several minutes. The cache volumes make later runs
quick.

**Done when** the demo ends with `demo complete`. If it doesn't, the daemon is broken before your
change is even exercised; fix that first.

## 3. Drive the changed behaviour

Copy `examples/demo.sh` to a scratch file outside the repo and replace the `exec` step with commands
that exercise the change. `sealantctl --help` lists the commands. Things to know:

- `sealantctl` streams live events only. It can't query past events, so capture its output as it
  runs (`> events.jsonl`).
- `sealantctl` exits 0 even when the child process fails. Read `process.exited` and its `exitCode`
  instead.
- To check behaviour through the TypeScript client, follow
  `packages/runtime-client/test/e2e.test.ts`, which spawns a daemon and drives it with
  `SealantClient`.

**Done when** the events you wrote down in step 1 appear, and you have also run the case that would
show the bug.

## 4. When the effect only shows end to end

Some changes only show through sealant or Mend, such as how a workspace starts or what a session
records. Use Mend's `verify` skill (`../mend/.claude/skills/verify/SKILL.md`). Its Launch section
takes `--sealantd <path|PR|ref>` to build this repo's change into a full stack.

## 5. Report

Put the verdict on the PR, and on the Linear ticket if there is one:

- the commit you ran;
- the commands you ran;
- the events that show the change working, trimmed to the lines that matter;
- anything you could not check, and why.
