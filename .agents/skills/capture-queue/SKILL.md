---
name: capture-queue
description: Keep the TLA+ model of the capture staging queue (docs/formal/capture-queue) true to the code. Use when a change touches Staging or the Shipper in sealant-capture's ship.rs, or the engine's snap, coalesce, hoist, repair or resume in engine.rs, or when `verify formal` fails the capture-queue guard.
---

# Capture staging queue model

`docs/formal/capture-queue/` models the staging queue with all its writers and a crash at any step.
Its `README.md` holds the promise, the invariants, the finding (SLNT-1009), the bounds and the action
table that maps each model action to the code. This skill is the procedure: decide whether a change
touches the model, run it, read what it says, and keep it true.

## 1. Account for each hunk

Diff the covered code from the sync commit (`COVERAGE`'s `sync` line) to your tree:

```sh
sync=$(sed -n 's/^sync //p' docs/formal/capture-queue/COVERAGE)
git diff "$sync" -- $(sed -n 's/^path //p' docs/formal/capture-queue/COVERAGE)
```

`engine.rs` is large and changes often. Read every hunk inside a function the README's action table
names, and anything that writes `queue/`, `restage.json`, `repair.json` or the shipper's `in_flight`.
Done when each such hunk has a model action it changes, or a reason it changes none.

## 2. Run the check

```sh
docs/formal/capture-queue/check.sh --quick   # while iterating: about 10 s
docs/formal/capture-queue/check.sh           # before moving the sync line: about 5 min
```

Each row prints `as expected` or `NOT AS EXPECTED`. A row is as expected only when its verdict and
its distinct-state count both match `ROWS` in `check.sh`. When an intended model change moves a
count, take the new one from a run at those bounds, full and `--quick`.

## 3. Classify a row that is not as expected

`check.sh <row>` (with `--quick` or not) prints TLC's whole trace. Walk every step against the code
its action names. A step is real when the code can take it in that state: its guards allow it, and
it is one rename, one removal or one registrar call there.

- **Every step real: a finding.** Write the trace as numbered steps in the code's words, reproduce
  it on the engine when you can (the in-memory registrar and a queue file put back stand in for a
  crash), and file it in Linear. Leave the invariant and the bounds as they are.
- **A step the code cannot take: a modelling error.** Usually a guard the action lacks, or two disk
  writes merged into one action. Fix the action, say in its comment what code it stands for, rerun.
- **A mutant that holds.** The code catches that break some other way now, or the model lost the
  behaviour the break needs. Pick a break that still matters and say why in `check.sh`.
- **`error`.** TLC did not finish: a parse error, `TypeOK`, or memory.

## 4. Update the model for an intended change

Change the action that stands for the code you changed; a new writer of the queue is a new action
in `Next` and a new line in the README's table. A fix keeps the old behaviour as a mutant expected
to fail. When SLNT-1009 is fixed, `Restart` takes the `Fix` branch, `Fix` goes, and the three
failing `code-` rows become rows that hold.

Then run the full check, update the counts in `ROWS` and the README, and move `COVERAGE`'s `sync`
line to the commit you checked.

## The guard

`pnpm verify formal` runs `check.sh --quick` when a diff touches `COVERAGE`'s paths or the model, and
reports drift: covered files changed since the sync commit. CI's `formal` job does the same on each
pull request, and fails a change to covered code that neither changes the model nor moves the sync
line. Move it only after steps 1 and 2. The nightly run checks the full bounds.
