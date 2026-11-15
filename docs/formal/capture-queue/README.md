# Capture staging queue model

`CaptureQueue.tla` models the capture staging queue (`crates/sealant-capture/src/ship.rs`) with
every writer it has: the engine's snaps, the shipper, and a process crash at any step followed by a
restart on the same disk. TLC checks every order of their steps within the bounds below.
`check.sh` runs it; the `capture-queue` skill (`.agents/skills/capture-queue`) is the procedure for
keeping it true to the code.

## The promise

Every capture that reaches the queue is registered once, in order, whatever step a crash lands on.

| Invariant                | In the code's words                                                                                                                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `NoLoss`                 | Every snap that reached the queue is held by the registrar's chain, by a queued entry, or by a committed `restage.json` (or the engine still writing a restage).                 |
| `NoDoubleShip`           | No snap's work is in two chain links, and no capture is two links.                                                                                                                  |
| `QueueContinuesChain`    | With no restage pending, each queued entry is the registered head (its ack lost), or the next `n` on the head, or the next `n` on the queued entry below it. What the restage journal exists for. |
| `AckedAreRegistered`     | `Staging::ack` removes a queue file only once the registrar holds that capture.                                                                                                      |
| `ClaimedNeverSuperseded` | The entry the shipper has claimed is never coalesced, hoisted or folded away under it.                                                                                               |
| `NoConflict`             | The registrar never answers this executor, the only writer of its chain, with wrong-parent. A capture it does would be sent again on every pass and never register, nor anything behind it. |

A snap is a token; a capture carries the tokens of every snap folded into it (a coalesce, a repair).
`NoLoss` and `NoDoubleShip` are stated over tokens.

## The finding, fixed (SLNT-1009)

The code before SLNT-1009 broke `QueueContinuesChain`, `NoConflict` and, with a second crash,
`NoLoss`. TLC's shortest trace, reproduced on the real engine with the in-memory registrar:

1. A snap stages an `auto` capture A at `n`. The shipper claims, uploads and registers it.
2. The process dies before `Staging::ack`. A is still queued; the registrar's head is A.
3. The restart resumes the queue (`pickup` says Resume; `resume_queue` continues from A).
4. The next snap, before the shipper sends A again, coalesces with A (`Staging::coalescible` sees
   the newest queued `auto` capture, not in flight): B takes A's `n` and A's parent.
5. The registrar's head is already at `n`: every pass answers B with wrong-parent.

With another snap (C at `n + 1`, parent B), a second crash and restart, the queue no longer descended
from the head. The engine continued from the head and its next snap wrote over C's queue file:
C's work was lost. (The boot's `pickup` also answered Materialize there and laid the head over the
disk.)

`resume_queue` now acks a queued capture the registrar holds as its head before anything snaps; the
model's `Restart` does the same. The old behaviour is kept as the `resume-keeps-registered` mutant,
expected to fail. The tests `a_capture_registered_before_a_crash_is_not_coalesced_with_after_the_restart`
and `edits_staged_after_a_lost_ack_survive_a_second_restart` (`crates/sealant-capture/tests/no_loss.rs`)
are the trace on the real engine.

## Rows and deliberate breaks

`check.sh` runs the rows in its `ROWS` table. The `code` row is the code: every invariant holds.
Each `mutant-` row breaks one mechanism, on a model where its invariant holds, and must be caught:

| Mutant                    | What it breaks                                                                                   | Caught by                                    |
| ------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------- |
| `resume-keeps-registered` | The restart leaves a registered capture queued (the code before SLNT-1009)                       | `QueueContinuesChain`, `NoConflict`, `NoLoss` |
| `no-journal`              | A restage writes its queue files one by one, with no `restage.json` to finish it after a crash    | `NoLoss`, `QueueContinuesChain`              |
| `no-cas`                  | The registrar appends whatever it is sent: a register sent again after a lost ack is a second link | `NoDoubleShip`                               |
| `ack-before-register`     | The shipper acks once the objects are up, before `capture.register`                              | `AckedAreRegistered`                         |
| `coalesce-in-flight`      | `coalescible` ignores the entry the shipper has claimed                                          | `ClaimedNeverSuperseded`                     |

`no-cas` runs together with `resume-keeps-registered`: the restart acks a registered capture, so the
code never sends one again, and a lost-ack answer is never asked for without it.

## Bounds

| Run            | Snaps | Crashes | Refusals | Time (4 workers)  |
| -------------- | ----- | ------- | -------- | ----------------- |
| `--quick` (PR) | 4     | 2       | 1        | about 10 s in all |
| full (nightly) | 6     | 3       | 2        | about 1 min       |

The quick bounds are the smallest that reach every break: the `resume-keeps-registered` `NoLoss`
trace needs four snaps and two crashes. `check.sh` pins each row's distinct-state count at both bounds.

## What each action stands for

| Action                                | Code                                                                                                     |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `SnapPlain`                           | `CaptureEngine::snap_preemptible`: `Staging::enqueue`, or `coalescible` then `Staging::replace`            |
| `SnapHoist`                           | `hoist_target`, `coalescible_below`, `restage_bulk`, then `Staging::restage` committing the journal        |
| `Repair`, `ClearRepair`               | `CaptureEngine::repair`: the rebuild's `Staging::restage`, then `clear_repair`                             |
| `ApplyWrite`, `ApplyRemove`, `ApplyDone` | `Staging::apply_restage`, by the engine or by `Staging::recover` from `Staging::open`                   |
| `Claim`                               | `Shipper::pass_once`: `restage_pending`, `awaiting_repair`, `Staging::claim` under the coalesce guard      |
| `Upload`                              | `upload_all` (every object put and marked)                                                                |
| `Register`                            | `register_one` against the registrar's CAS (`Registrar::capture_register`)                                |
| `Ack`                                 | `Staging::ack` (by the entry's `n`), then `release`                                                        |
| `ClearStaleRepair`                    | `pass_once` clearing a repair for a capture no longer queued                                              |
| `Crash`, `Restart`                    | The process dies; `CaptureEngine::pickup`, `Staging::open`, `CaptureEngine::open` and `resume_queue` (its ack of a registered head first) |

## Assumptions and what is left out

- **Process crashes, not power loss.** What a rename put on disk survives. `Staging::enqueue` does not
  fsync its temporary file, unlike the restage journal; a power loss after the rename could leave an
  empty entry that `pending()` skips. The model does not cover that.
- Objects and upload markers are "uploaded or not": uploads are idempotent per key, and the sweep
  removes only what no queued entry lists.
- Every snap is `auto`, so any newest entry can be coalesced: the most permissive case.
- A bulk capture's unclaimed uploads, a byte-quota hold, a lease or registrar outage and a re-plan
  (foreign entries, `discard_foreign`, `discard_all`) are left out. An outage only delays the
  shipper, which the model already allows at every step. Foreign and standby drops are deliberate
  and the disk is snapped again.
- A repair rebuilds one class. The code may rebuild both, one restage each.
- The removals of a restage are one step. Recovery repeats them whole, so a crash between two of
  them reaches no state the model misses.
