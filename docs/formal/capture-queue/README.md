# Capture staging queue model

`CaptureQueue.tla` models the capture staging queue (`crates/sealant-capture/src/ship.rs`) with
every writer it has: the engine's snaps, the shipper, and a process crash at any step followed by a
restart on the same disk. Its `replan` rows add a standby: the executor starts under a placeholder
identity, stages a capture there that no registrar takes, and a re-plan (`capture.replan`) moves it
onto the session at any step, the shipper possibly on that capture. tlx, the Rust model checker,
checks every order of their steps within the bounds below.
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
| `ClaimedNeverSuperseded` | The entry the shipper has claimed is never coalesced, hoisted or folded away under it (one staged under the current identity: a foreign one is the session's first capture's to write over). |
| `ForeignOnlyInFlight`    | An entry staged under another identity than the current one is queued only while the shipper is on it: the rebase drops the others, the shipper letting go of it drops it, and so does a restart. |
| `NoConflict`             | The registrar never answers this executor, the only writer of its chain, with wrong-parent. A capture it does would be sent again on every pass and never register, nor anything behind it. |

A snap is a token; a capture carries the tokens of every snap folded into it (a coalesce, a repair).
`NoLoss` and `NoDoubleShip` are stated over tokens. The standby's capture holds no token: nothing of
the session's is on it, and dropping it is the point. `QueueContinuesChain` is stated over the
session's entries.

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

## The finding, fixed (SLNT-1059)

On a Mend server with hot sessions, 2 of 13 claimed standbys never saved the session's work: the stop
read `not saved · workspace kept`. The code before SLNT-1059 breaks `QueueContinuesChain` and
`NoConflict` in the `replan` rows (`mutant-before-slnt-1059-*`), in five steps:

1. The standby snaps under its placeholder: P at `n = 1`, parent the placeholder's base.
2. The shipper claims P (a retry after `lease-lost`).
3. The claim's re-plan rebases: `discard_foreign` skips P, in flight.
4. P's register answers `lease-lost`; the shipper lets go of it, and it stays queued.
5. The session's first `auto` snap coalesces with P: it takes P's `n`, P's parent (on no chain of the
   session's) and P's packs. Every register is wrong-parent (Mend also mints no URL for the packs).

Now `coalescible` skips a foreign entry (`coalesce-foreign` is the old guard), the shipper letting
go of a foreign entry drops it (`keep-foreign`), and `ack` and the release remove a queue file only
if it still holds the capture the shipper claimed (`by-n` removes whatever is at that `n`). The
last matters because the session's first capture takes P's `n` (the head's `n + 1`, the only one
the registrar takes): with the snap between steps 3 and 4, it writes over P's queue file while the
shipper is on P, and a release by `n` then removed the session's capture (`mutant-by-n`, `NoLoss`).
`crates/sealant-capture/tests/replan_in_flight.rs` runs each order on the real engine.

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
| `keep-foreign` (`replan`) | The shipper letting go of a foreign entry leaves it queued (the release before SLNT-1059)         | `ForeignOnlyInFlight`; with `coalesce-foreign`, `QueueContinuesChain` |
| `coalesce-foreign` (`replan`) | `coalescible` and `coalescible_below` take a foreign entry (before SLNT-1059). Alone it holds: no foreign entry is left to take | with `keep-foreign`, `QueueContinuesChain` |
| `by-n` (`replan`)         | `ack` and the release remove whatever is queued at the claimed entry's `n` (before SLNT-1059)     | `NoLoss`                                     |

`no-cas` runs together with `resume-keeps-registered`: the restart acks a registered capture, so the
code never sends one again, and a lost-ack answer is never asked for without it. `coalesce-foreign`
runs together with `keep-foreign` for the same reason: either fix alone keeps the session's capture
off the placeholder's chain. `mutant-before-slnt-1059-*` runs all three, the code as it was.

## Bounds

| Run            | Snaps | Crashes | Refusals | Time (tlx, 4 workers) |
| -------------- | ----- | ------- | -------- | --------------------- |
| `--quick` (PR) | 4     | 2       | 1        | about 2 s in all      |
| full (nightly) | 6     | 3       | 2        | about 30 s in all     |

The quick bounds are the smallest that reach every break: the `resume-keeps-registered` `NoLoss`
trace needs four snaps and two crashes. The `replan` rows run at the same bounds plus the standby's
one capture: the `replan` code row holds over 17,207,138 distinct states at full bounds (about
16 s) and 123,799 at the quick ones. `check.sh` pins each row's distinct-state count at both bounds.

## tlx and TLC

tlx ([tlaplus-x/tlx](https://github.com/tlaplus-x/tlx), version 0.1, no releases) is the checker of
record. `check.sh` runs it with `-tlc`, its mode that promises TLC's verdicts, distinct-state
counts, depth and shortest traces. `../tlx.sh` pins the commit
(`8d5f082b0f0d922bf5999d9a8db00c70a4c1d261`, the one Mend measured and tlx's newest on 17 Nov 2026)
and builds it into `~/.cache/sealantd-formal/tlx-<commit>/` the first time. That needs git, cargo
and a C compiler, and takes about 2 minutes on 4 jobs. `FORMAL_TLX` names another binary instead.
CI caches the binary by the commit.

TLC (tla2tools 1.7.4) stays as `check.sh --engine tlc` (or `FORMAL_ENGINE=tlc`) for a cross-check by
hand; it needs java. Nothing scheduled runs it.

Before the switch (SLNT-1081, 17 Nov 2026) both checkers ran every row at both bounds, on 4 workers
for a row that holds and one for a row that must fail. Every verdict, violated invariant,
distinct-state count, generated-state count and trace length matched, and every row that must fail
failed under both. So did the search depth of every row but `code`, where TLC on 4 workers said 71
and tlx 70; TLC on one worker says 70 (its depth on several workers is approximate). On a shared
32-core machine:

| Run                          | TLC           | tlx          |
| ---------------------------- | ------------- | ------------ |
| `code`, full bounds          | 33 s          | 8 s          |
| `replan`, full bounds        | 70 s          | 16 s         |
| whole `check.sh` (wall, RSS) | 112 s, 6.9 GB | 29 s, 1.9 GB |
| whole `check.sh --quick`     | 11 s          | 2 s          |

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
| `Ack`                                 | `Staging::ack` (the entry's queue file, if it still holds that capture), then `release`                    |
| `LetGoForeign`                        | `pass_once` on a foreign entry, at its claim or failed in flight: `Staging::release` drops it (by capture id) |
| `RegisterStandby`                     | The placeholder's `capture.register`: `lease-lost` and `release`, or taken on the standby's own chain      |
| `StandbySnap`                         | A standby's `auto` snap under its placeholder identity (one, in the `replan` rows)                         |
| `Rebase`                              | `capture.replan`'s `CaptureEngine::rebase`: `Staging::set_identity`, then `discard_foreign` (skips the entry in flight) |
| `ClearStaleRepair`                    | `pass_once` clearing a repair for a capture no longer queued                                              |
| `Crash`, `Restart`                    | The process dies; `CaptureEngine::pickup`, `Staging::open`, `CaptureEngine::open` (its `discard_foreign`) and `resume_queue` (its ack of a registered head first) |

## Assumptions and what is left out

- **Process crashes, not power loss.** What a rename put on disk survives. `Staging::enqueue` does not
  fsync its temporary file, unlike the restage journal; a power loss after the rename could leave an
  empty entry that `pending()` skips. The model does not cover that.
- Objects and upload markers are "uploaded or not": uploads are idempotent per key, and the sweep
  removes only what no queued entry lists.
- Every snap is `auto`, so any newest entry can be coalesced: the most permissive case.
- A bulk capture's unclaimed uploads, a byte-quota hold, a lease or registrar outage and
  `discard_all` (a standby no session claimed) are left out. An outage only delays the shipper,
  which the model already allows at every step.
- The re-plan (`replan` rows) is one, from a standby onto a session whose chain is empty, so the
  session's first capture takes the placeholder capture's `n`. The standby stages one capture and
  does not crash before its claim (it would boot again as a standby, with nothing of a session on
  it). A second re-plan onto another identity is left out: its rebase drops the first session's
  unregistered captures by design, the old epoch's, which can never register.
- Where the objects of a dropped or written-over entry go (`Staging::sweep` from the release or from
  `enqueue`) is not modelled; `tests/replan_in_flight.rs` checks they are swept.
- A repair rebuilds one class. The code may rebuild both, one restage each.
- The removals of a restage are one step. Recovery repeats them whole, so a crash between two of
  them reaches no state the model misses.
