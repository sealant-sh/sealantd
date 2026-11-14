---
name: verify
description: Run a real sealantd, drive it with a driver script, and keep the event stream as evidence. Use to prove a sealantd change works beyond its tests, before opening or merging its PR.
---

# Verify a sealantd change

Prove the change by running the real daemon and reading what it records. A green test suite says the
code does what the tests ask; this says the daemon does what the change claims.

Run `pnpm verify plan` first: it lists what the change owes. This skill discharges its `stack`
obligation.

## 1. Say what you expect to see

Before running anything, write down the events or output the change should produce, and what you
would see if it were broken. For example: "a secret written in two parts appears masked in both
`io.chunk` events". This is the claim the run checks.

## 2. Drive the changed behaviour

Copy `tooling/verify/drivers/exec.mjs` to a scratch file outside the repo and change its middle to
exercise the change. Its header lists what the driver receives. Then:

```sh
pnpm verify daemon --driver <file>            # extra daemon flags go after `--`
```

It builds the daemon from this tree, starts it on a scratch socket and workspace, waits until it
answers healthy, runs the driver, records every event to `events.jsonl` beside the daemon's log, and
tears everything down. `--keep` leaves the daemon running and prints how to reach and stop it.

- The driver decides the verdict: exit 0 only when the behaviour held. An exec's response and
  `sealantctl` both report success for a command that failed; the `processExited` event says.
- It needs Linux with Rust and Node, as the daemon does; the `rust` container AGENTS.md names
  for Macs has no Node.

**Done when** the events you wrote down in step 1 are in `events.jsonl`, and a driver for the case
that would show the bug has failed on the old behaviour or passed on the new.

## 3. When the effect only shows end to end

Some changes only show through sealant or Mend, such as how a workspace starts or what a session
records. Use Mend's `verify` skill (`../mend/.claude/skills/verify/SKILL.md`). Its Launch section
takes `--sealantd <path|PR|ref>` to build this repo's change into a full stack.

## 4. Report

Put the verdict on the PR, and on the Linear ticket if there is one: `pnpm verify status --markdown`
for the receipt, the events that show the change working (trimmed to the lines that matter), and
anything you could not check, and why.
