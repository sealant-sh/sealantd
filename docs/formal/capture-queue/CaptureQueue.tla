---------------------------- MODULE CaptureQueue ----------------------------
(***************************************************************************)
(* The capture staging queue (crates/sealant-capture/src/ship.rs) with its  *)
(* writers: the engine's snaps (enqueue, coalesce, the journaled restage of *)
(* a hoist or a repair), the shipper (claim, upload, register, ack) and a   *)
(* process crash at any step, after which the daemon reopens its staging    *)
(* (Staging::open finishes a committed restage) and resumes the queue       *)
(* (CaptureEngine::resume_queue). With Replan, the executor starts as a    *)
(* standby under a placeholder identity whose captures no registrar takes,  *)
(* stages one, and a re-plan (capture.replan's CaptureEngine::rebase) moves *)
(* it onto the session at any step, the shipper possibly on that capture.   *)
(* README.md beside this file says what each action stands for in the code, *)
(* the bounds and what is left out.                                          *)
(*                                                                           *)
(* A snap is a token 1..MaxSnaps: the work it saved. A capture (a queue     *)
(* entry, a chain link) carries the tokens of every snap folded into it.    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    MaxSnaps,     \* snaps the engine takes
    MaxCrashes,   \* process crashes
    MaxRefusals,  \* registrar refusals (422 missing-objects), each answered by a repair
    Replan,       \* TRUE: a standby, claimed by a re-plan; FALSE: the session from the start
    Mutants       \* {} is the code; README.md lists the deliberate breaks

Classes == {"small", "bulk"}
Snaps == 1..MaxSnaps
\* Every manifest the engine writes gets a fresh id: a snap writes one, a hoist two, a repair one.
\* With Replan, the standby's one capture too.
MaxId == 2 * MaxSnaps + MaxRefusals + (IF Replan THEN 1 ELSE 0)
Ids == 1..MaxId
NoId == 0
\* The placeholder's base capture: the standby's chain head, on no chain of the session's.
PBase == MaxId + 1

\* ident: the identity (worktree, epoch) the entry was staged under. The session's chain is the
\* registrar's `chain`; the placeholder's is another, which answers its captures lease-lost (the
\* standby holds no lease) or, at most, takes them without touching the session's.
Idents == {"standby", "session"}
Entry == [id: Ids, n: 1..MaxId, parent: Ids \cup {NoId, PBase}, content: SUBSET Snaps,
          class: Classes, ident: Idents]

VARIABLES
    \* On disk: they survive a crash.
    queue,      \* the files under queue/: a set of entries, one per n
    jpending,   \* restage.json is committed
    journal,    \* what it holds: [write: Seq(Entry), sup: SUBSET Entry, repair: BOOLEAN]
    repairReq,  \* repair.json: the id of the capture to rebuild, or NoId
    \* The registrar: survives a crash.
    chain,      \* the registered captures, chain[i].n = i
    \* In memory: lost in a crash.
    up,         \* the process is running (FALSE: down, or reopening its staging)
    eng,        \* the engine: "idle", "restage" (applying a journal), "clear" (repair applied)
    jstep,      \* the next journal write to apply (Len(write) + 1: the removals; + 2: done)
    prev,       \* the capture the next snap continues: [id, n]
    ship,       \* the shipper: [st: "idle" | "claimed" | "uploaded" | "registered", e: Entry]
    nextId,
    ident,      \* the identity staging is under now (Staging::identity; the plan's at a restart)
    \* Counters and ghosts.
    snaps, crashes, refusals,
    ssnaps,     \* snaps the standby took under its placeholder
    staged,     \* tokens of every snap that reached the queue (or a committed journal)
    acked,      \* ids the shipper removed from the queue by an ack
    conflicted  \* the registrar answered wrong-parent

vars == <<queue, jpending, journal, repairReq, chain, up, eng, jstep, prev, ship, nextId, ident,
          snaps, crashes, refusals, ssnaps, staged, acked, conflicted>>

NoEntry == [id |-> NoId, n |-> 0, parent |-> NoId, content |-> {}, class |-> "small",
            ident |-> "session"]
NoJournal == [write |-> << >>, sup |-> {}, repair |-> FALSE]
Idle == [st |-> "idle", e |-> NoEntry]

----------------------------------------------------------------------------
\* Helpers.

Max(S) == CHOOSE x \in S : \A y \in S : y <= x
Range(s) == {s[i] : i \in DOMAIN s}

HeadN == Len(chain)
HeadId == IF chain = << >> THEN NoId ELSE chain[Len(chain)].id
ChainIds == {chain[i].id : i \in DOMAIN chain}

At(n) == {e \in queue : e.n = n}
Oldest == CHOOSE e \in queue : \A f \in queue : e.n <= f.n
Newest == CHOOSE e \in queue : \A f \in queue : f.n <= e.n

InFlight == IF ship.st = "idle" THEN NoId ELSE ship.e.id

\* A write over the file at e.n (write-then-rename: one atomic step).
Put(q, e) == {x \in q : x.n # e.n} \cup {e}

\* Remove the queue file of e, the capture the shipper was on (Staging::ack, Staging::release):
\* only if it still holds e. "by-n" removes whatever is at e.n, as ack did before SLNT-1059.
Unqueue(q, e) == IF "by-n" \in Mutants THEN {x \in q : x.n # e.n} ELSE {x \in q : x.id # e.id}

\* The shipper lets go of e without registering it (Staging::release): an entry staged under
\* another identity than the current one is dropped then. "keep-foreign" leaves it queued, as
\* release did before SLNT-1059.
LetGo(q, e) == IF e.ident # ident /\ "keep-foreign" \notin Mutants THEN Unqueue(q, e) ELSE q

\* What restart takes as the capture to continue from queue q (resume_queue): the newest queued
\* capture when q descends from the registered head, else the head.
ResumeFrom(q) ==
    IF q # {} /\ \E e \in q : e.parent = HeadId \/ e.id = HeadId
    THEN LET newest == CHOOSE e \in q : \A f \in q : f.n <= e.n
         IN [id |-> newest.id, n |-> newest.n]
    ELSE [id |-> HeadId, n |-> HeadN]

----------------------------------------------------------------------------
Init ==
    /\ queue = {}
    /\ jpending = FALSE
    /\ journal = NoJournal
    /\ repairReq = NoId
    /\ chain = << >>
    /\ up = TRUE
    /\ eng = "idle"
    /\ jstep = 1
    /\ prev = IF Replan THEN [id |-> PBase, n |-> 0] ELSE [id |-> NoId, n |-> 0]
    /\ ship = Idle
    /\ nextId = 1
    /\ ident = IF Replan THEN "standby" ELSE "session"
    /\ snaps = 0
    /\ crashes = 0
    /\ refusals = 0
    /\ ssnaps = 0
    /\ staged = {}
    /\ acked = {}
    /\ conflicted = FALSE

----------------------------------------------------------------------------
\* The engine.

\* A snap waits for a pending repair (snap_preemptible runs the repair first) and for a restage.
\* The session's snaps run once it is the session's (a standby has no session work to snap).
EngineFree == up /\ eng = "idle" /\ ~jpending /\ ~(\E e \in queue : e.id = repairReq)
              /\ ident = "session"

\* Staging::coalescible: the newest queued capture, of the snap's class, that the shipper is not
\* on, staged under the current identity ("coalesce-foreign": under any, as before SLNT-1059).
CanCoalesce(class) ==
    /\ queue # {}
    /\ Newest.class = class
    /\ ("coalesce-in-flight" \in Mutants \/ Newest.id # InFlight)
    /\ ("coalesce-foreign" \in Mutants \/ Newest.ident = ident)

\* CaptureEngine::hoist_target: a small snap goes ahead of the newest queued capture when it is a
\* bulk one the shipper is not on and the engine staged it last.
CanHoist(class) ==
    /\ class = "small"
    /\ queue # {}
    /\ Newest.class = "bulk"
    /\ Newest.id # InFlight
    /\ Newest.ident = ident
    /\ prev.id = Newest.id

\* Enqueue at the end of the chain, or coalesce with the newest queued capture (replace: the new
\* manifest renamed over the old one's file, at its n, with its parent).
SnapPlain(class) ==
    /\ EngineFree
    /\ snaps < MaxSnaps
    /\ ~CanHoist(class)
    /\ LET s == snaps + 1
           old == Newest
           e == IF CanCoalesce(class)
                THEN [id |-> nextId, n |-> old.n, parent |-> old.parent,
                      content |-> old.content \cup {s}, class |-> class, ident |-> ident]
                ELSE [id |-> nextId, n |-> prev.n + 1, parent |-> prev.id,
                      content |-> {s}, class |-> class, ident |-> ident]
       IN /\ queue' = Put(queue, e)
          /\ prev' = [id |-> e.id, n |-> e.n]
          /\ snaps' = s
          /\ nextId' = nextId + 1
          /\ staged' = staged \cup {s}
    /\ UNCHANGED <<jpending, journal, repairReq, chain, up, eng, jstep, ship, ident, crashes,
                   refusals, ssnaps, acked, conflicted>>

\* A small snap staged ahead of the queued bulk capture B: the small capture S takes B's place (or,
\* coalescing the small capture right below B, that one's), B is written again at S.n + 1 on S.
\* Staging::restage commits it as one journal; the queue changes as eng = "restage" applies it.
SnapHoist ==
    /\ EngineFree
    /\ snaps < MaxSnaps
    /\ CanHoist("small")
    /\ LET s == snaps + 1
           b == Newest
           belowNs == {f.n : f \in {x \in queue : x.n < b.n}}
           below == IF belowNs = {} THEN NoEntry ELSE CHOOSE f \in At(Max(belowNs)) : TRUE
           fold == /\ below # NoEntry /\ below.class = "small" /\ below.id # InFlight
                   /\ ("coalesce-foreign" \in Mutants \/ below.ident = ident)
           small == IF fold
                    THEN [id |-> nextId, n |-> below.n, parent |-> below.parent,
                          content |-> below.content \cup {s}, class |-> "small", ident |-> ident]
                    ELSE [id |-> nextId, n |-> b.n, parent |-> b.parent,
                          content |-> {s}, class |-> "small", ident |-> ident]
           moved == [id |-> nextId + 1, n |-> small.n + 1, parent |-> small.id,
                     content |-> b.content, class |-> "bulk", ident |-> ident]
           j == [write |-> <<moved, small>>,
                 sup |-> IF fold THEN {b, below} ELSE {b},
                 repair |-> FALSE]
       IN /\ journal' = j
          /\ prev' = [id |-> moved.id, n |-> moved.n]
          /\ snaps' = s
          /\ nextId' = nextId + 2
          /\ staged' = staged \cup {s}
          /\ IF "no-journal" \in Mutants
             \* The restage as it was: the queue files written one by one, nothing to finish it.
             THEN /\ jpending' = FALSE
                  /\ eng' = "restage"
             ELSE /\ jpending' = TRUE
                  /\ eng' = "restage"
    /\ jstep' = 1
    /\ UNCHANGED <<queue, repairReq, chain, up, ship, ident, crashes, refusals, ssnaps, acked,
                   conflicted>>

\* CaptureEngine::repair: the refused capture rebuilt from disk at its n with its parent, every
\* capture staged after it under the same identity folded in, as one journaled restage. A capture
\* staged under another identity is never rebuilt (the shipper asks no repair for one).
Repair ==
    /\ up /\ eng = "idle" /\ ~jpending
    /\ \E r \in queue :
        /\ r.id = repairReq
        /\ r.ident = ident
        /\ LET followers == {f \in queue : f.n > r.n /\ f.ident = ident}
               rebuilt == [id |-> nextId, n |-> r.n, parent |-> r.parent,
                           content |-> UNION {f.content : f \in followers \cup {r}},
                           class |-> r.class, ident |-> ident]
           IN /\ journal' = [write |-> <<rebuilt>>, sup |-> followers \cup {r}, repair |-> TRUE]
              /\ prev' = [id |-> rebuilt.id, n |-> rebuilt.n]
    /\ jpending' = ("no-journal" \notin Mutants)
    /\ eng' = "restage"
    /\ jstep' = 1
    /\ nextId' = nextId + 1
    /\ UNCHANGED <<queue, repairReq, chain, up, ship, ident, snaps, crashes, refusals, ssnaps,
                   staged, acked, conflicted>>

\* One step of applying the journal (apply_restage): each write, then the removals of superseded
\* files no write took, then the journal removed. Run by the engine that committed it, or by
\* Staging::open (up = FALSE) after a crash, from the first write again: every step is idempotent.
Applying == (up /\ eng = "restage") \/ (~up /\ jpending)

ApplyWrite ==
    /\ Applying
    /\ jstep <= Len(journal.write)
    /\ queue' = Put(queue, journal.write[jstep])
    /\ jstep' = jstep + 1
    /\ UNCHANGED <<jpending, journal, repairReq, chain, up, eng, prev, ship, nextId, snaps,
                   crashes, refusals, staged, acked, conflicted, ident, ssnaps>>

ApplyRemove ==
    /\ Applying
    /\ jstep = Len(journal.write) + 1
    /\ LET written == {journal.write[i].n : i \in DOMAIN journal.write}
           gone == {x.n : x \in journal.sup} \ written
       IN queue' = {x \in queue : x.n \notin gone}
    /\ jstep' = jstep + 1
    /\ UNCHANGED <<jpending, journal, repairReq, chain, up, eng, prev, ship, nextId, snaps,
                   crashes, refusals, staged, acked, conflicted, ident, ssnaps>>

ApplyDone ==
    /\ Applying
    /\ jstep = Len(journal.write) + 2
    /\ jpending' = FALSE
    /\ journal' = NoJournal
    /\ jstep' = 1
    /\ eng' = IF up /\ journal.repair THEN "clear" ELSE "idle"
    /\ UNCHANGED <<queue, repairReq, chain, up, prev, ship, nextId, snaps, crashes, refusals,
                   staged, acked, conflicted, ident, ssnaps>>

\* The repair is done: repair.json removed.
ClearRepair ==
    /\ up /\ eng = "clear"
    /\ repairReq' = NoId
    /\ eng' = "idle"
    /\ UNCHANGED <<queue, jpending, journal, chain, up, jstep, prev, ship, nextId, snaps,
                   crashes, refusals, staged, acked, conflicted, ident, ssnaps>>

----------------------------------------------------------------------------
\* The shipper (Shipper::pass_once). It claims the oldest entry under the coalesce guard, which the
\* engine holds while it applies a restage, and starts no pass while a restage is pending.

\* A repair asked for a capture no longer queued is done (pass_once clears it).
ClearStaleRepair ==
    /\ up /\ ship.st = "idle"
    /\ repairReq # NoId
    /\ ~(\E e \in queue : e.id = repairReq)
    /\ repairReq' = NoId
    /\ UNCHANGED <<queue, jpending, journal, chain, up, eng, jstep, prev, ship, nextId, snaps,
                   crashes, refusals, staged, acked, conflicted, ident, ssnaps>>

Claim ==
    /\ up /\ ship.st = "idle"
    /\ eng # "restage" /\ ~jpending
    /\ queue # {}
    /\ Oldest.id # repairReq
    /\ ship' = [st |-> "claimed", e |-> Oldest]
    /\ UNCHANGED <<queue, jpending, journal, repairReq, chain, up, eng, jstep, prev, nextId,
                   snaps, crashes, refusals, staged, acked, conflicted, ident, ssnaps>>

\* pass_once on an entry staged under another identity than the current one, found at its claim
\* or failed in flight after a re-plan moved the identity under it: the shipper lets go of it
\* (Staging::release), which drops it. Its answer pauses nothing and asks for no repair.
LetGoForeign ==
    /\ up /\ ship.st \in {"claimed", "uploaded"}
    /\ ship.e.ident # ident
    /\ queue' = LetGo(queue, ship.e)
    /\ ship' = Idle
    /\ UNCHANGED <<jpending, journal, repairReq, chain, up, eng, jstep, prev, nextId, snaps,
                   crashes, refusals, staged, acked, conflicted, ident, ssnaps>>

\* Every object the entry lists is put (and acked as uploaded): idempotent, so not modelled further.
Upload ==
    /\ up /\ ship.st = "claimed"
    /\ ship' = [ship EXCEPT !.st = "uploaded"]
    /\ UNCHANGED <<queue, jpending, journal, repairReq, chain, up, eng, jstep, prev, nextId,
                   snaps, crashes, refusals, staged, acked, conflicted, ident, ssnaps>>

\* capture.register, the registrar's CAS: the next n on the head is appended; the head itself sent
\* again is a lost ack, answered as success; anything else is wrong-parent. Or 422: refused, and a
\* repair is asked for.
Register ==
    /\ up /\ ship.st = "uploaded"
    /\ ship.e.ident = "session"
    /\ LET e == ship.e
           lostAck == chain # << >> /\ e.n = HeadN /\ e.id = HeadId
           next == e.n = HeadN + 1 /\ e.parent = HeadId
       IN \/ /\ "no-cas" \in Mutants
             \* A registrar that appends whatever it is sent.
             /\ chain' = Append(chain, e)
             /\ ship' = [ship EXCEPT !.st = "registered"]
             /\ UNCHANGED <<repairReq, refusals, conflicted>>
          \/ /\ "no-cas" \notin Mutants
             /\ \/ /\ lostAck
                   /\ ship' = [ship EXCEPT !.st = "registered"]
                   /\ UNCHANGED <<chain, repairReq, refusals, conflicted>>
                \/ /\ next
                   /\ chain' = Append(chain, e)
                   /\ ship' = [ship EXCEPT !.st = "registered"]
                   /\ UNCHANGED <<repairReq, refusals, conflicted>>
                \/ /\ next
                   /\ refusals < MaxRefusals
                   /\ repairReq' = e.id
                   /\ refusals' = refusals + 1
                   /\ ship' = Idle
                   /\ UNCHANGED <<chain, conflicted>>
                \/ /\ ~lostAck /\ ~next
                   \* ShipError::Conflict: the pass ends; the next pass sends it again.
                   /\ conflicted' = TRUE
                   /\ ship' = Idle
                   /\ UNCHANGED <<chain, repairReq, refusals>>
    /\ UNCHANGED <<queue, jpending, journal, up, eng, jstep, prev, nextId, snaps, crashes,
                   staged, acked, ident, ssnaps>>

\* The placeholder's capture.register, on the standby's own chain: lease-lost (no lease before
\* the claim), and the shipper lets go of it (dropped if a re-plan made it foreign meanwhile);
\* or, for a lease that was live, taken there, never on the session's chain.
RegisterStandby ==
    /\ up /\ ship.st = "uploaded"
    /\ ship.e.ident = "standby"
    /\ \/ /\ queue' = LetGo(queue, ship.e)
          /\ ship' = Idle
       \/ /\ ship' = [ship EXCEPT !.st = "registered"]
          /\ UNCHANGED queue
    /\ UNCHANGED <<jpending, journal, repairReq, chain, up, eng, jstep, prev, nextId, snaps,
                   crashes, refusals, staged, acked, conflicted, ident, ssnaps>>

\* Staging::ack: the entry's queue file removed if it still holds that capture (then its objects
\* swept), and released. The placeholder's ack is the standby registrar's, not in `acked`.
Ack ==
    /\ up
    /\ \/ ship.st = "registered"
       \/ "ack-before-register" \in Mutants /\ ship.st = "uploaded"
    /\ queue' = Unqueue(queue, ship.e)
    /\ acked' = IF ship.e.ident = "session" THEN acked \cup {ship.e.id} ELSE acked
    /\ ship' = Idle
    /\ UNCHANGED <<jpending, journal, repairReq, chain, up, eng, jstep, prev, nextId, snaps,
                   crashes, refusals, staged, conflicted, ident, ssnaps>>

----------------------------------------------------------------------------
\* The standby and its re-plan.

\* The standby's snap of its first minute, under its placeholder: it continues the placeholder's
\* base and holds nothing of the session's.
StandbySnap ==
    /\ up /\ eng = "idle" /\ ~jpending
    /\ ident = "standby"
    /\ ssnaps < 1
    /\ LET e == [id |-> nextId, n |-> prev.n + 1, parent |-> prev.id, content |-> {},
                 class |-> "small", ident |-> "standby"]
       IN /\ queue' = Put(queue, e)
          /\ prev' = [id |-> e.id, n |-> e.n]
    /\ nextId' = nextId + 1
    /\ ssnaps' = ssnaps + 1
    /\ UNCHANGED <<jpending, journal, repairReq, chain, up, eng, jstep, ship, ident, snaps,
                   crashes, refusals, staged, acked, conflicted>>

\* capture.replan: CaptureEngine::rebase moves staging onto the session (Staging::set_identity),
\* drops every foreign entry the shipper is not on (Staging::discard_foreign) and continues from
\* the session's head. No snap runs meanwhile (it holds the engine).
Rebase ==
    /\ up /\ eng = "idle" /\ ~jpending
    /\ ident = "standby"
    /\ ident' = "session"
    /\ queue' = {x \in queue : x.ident = "session" \/ x.id = InFlight}
    /\ prev' = [id |-> HeadId, n |-> HeadN]
    /\ UNCHANGED <<jpending, journal, repairReq, chain, up, eng, jstep, ship, nextId, snaps,
                   crashes, refusals, ssnaps, staged, acked, conflicted>>

----------------------------------------------------------------------------
\* Crash and restart.

\* A standby that dies before its claim boots again as a standby: nothing of a session is on it.
Crash ==
    /\ crashes < MaxCrashes
    /\ ident = "session"
    /\ up' = FALSE
    /\ eng' = "idle"
    /\ jstep' = 1
    /\ ship' = Idle
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<queue, jpending, journal, repairReq, chain, prev, nextId, snaps, refusals,
                   staged, acked, conflicted, ident, ssnaps>>

\* Staging::open has finished any committed restage (ApplyWrite.. with up = FALSE); the engine
\* opens on the registered head and resume_queue acks a queued capture the registrar holds as its
\* head (registered, its ack lost) before anything snaps (SLNT-1009). Then it continues from the
\* queue. "resume-keeps-registered" is the code before SLNT-1009: the capture stays queued.
\* CaptureEngine::open drops the entries staged under another identity first (discard_foreign):
\* a re-plan's placeholder capture the shipper was on when the process died.
Restart ==
    /\ ~up /\ ~jpending
    /\ up' = TRUE
    /\ LET own == {x \in queue : x.ident = ident}
           q == IF "resume-keeps-registered" \in Mutants
                THEN own
                ELSE {x \in own : ~(x.id = HeadId /\ x.n = HeadN)}
       IN /\ queue' = q
          /\ prev' = ResumeFrom(q)
          /\ acked' = acked \cup {x.id : x \in own \ q}
    /\ UNCHANGED <<jpending, journal, repairReq, chain, eng, jstep, ship, nextId, snaps, crashes,
                   refusals, staged, conflicted, ident, ssnaps>>

----------------------------------------------------------------------------
Next ==
    \/ \E c \in Classes : SnapPlain(c)
    \/ SnapHoist
    \/ Repair
    \/ ApplyWrite \/ ApplyRemove \/ ApplyDone \/ ClearRepair
    \/ ClearStaleRepair \/ Claim \/ Upload \/ Register \/ Ack
    \/ LetGoForeign \/ RegisterStandby \/ StandbySnap \/ Rebase
    \/ Crash \/ Restart

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* Invariants. README.md states each in the code's words.

TypeOK ==
    /\ queue \subseteq Entry
    /\ jpending \in BOOLEAN
    /\ repairReq \in Ids \cup {NoId}
    /\ up \in BOOLEAN
    /\ eng \in {"idle", "restage", "clear"}
    /\ ship.st \in {"idle", "claimed", "uploaded", "registered"}
    /\ ident \in Idents
    /\ \A x, y \in queue : x.n = y.n => x = y

\* A restage's captures are held by its committed journal, or, before it commits or with no
\* journal, by the engine still writing them.
Held == queue \cup Range(chain)
        \cup (IF jpending \/ (up /\ eng = "restage") THEN Range(journal.write) ELSE {})

\* I1: nothing staged is lost.
NoLoss == \A s \in staged : \E e \in Held : s \in e.content

\* I2: nothing is shipped twice: no snap's work is in two chain links, no capture is two links.
NoDoubleShip ==
    \A i, j \in DOMAIN chain :
        i # j => chain[i].id # chain[j].id /\ chain[i].content \cap chain[j].content = {}

\* I3: the queue continues the chain. With no restage pending, each queued capture is the head
\* (its ack lost), or the next n on the head, or the next n on the queued capture below it.
QueueContinuesChain ==
    ~jpending =>
        \A e \in {x \in queue : x.ident = "session"} :
            \/ e.n = HeadN /\ e.id = HeadId
            \/ e.n = HeadN + 1 /\ e.parent = HeadId
            \/ e.n > HeadN + 1 /\ \E f \in queue : f.n = e.n - 1 /\ f.id = e.parent

\* I4: a queue file leaves by an ack only once the registrar holds its capture.
AckedAreRegistered == acked \subseteq ChainIds

\* I5: the entry the shipper holds is never superseded under it.
\* (A capture staged under another identity is not the session's: the session's first capture
\* takes its n, and writes over it.)
ClaimedNeverSuperseded ==
    ship.st # "idle" /\ ship.e.ident = ident =>
        (\E e \in queue : e.id = ship.e.id) \/ ship.e.id \in ChainIds

\* I6: a capture staged under another identity is queued only while the shipper is on it: the
\* rebase drops the others, letting go of it drops it, and so does a restart.
ForeignOnlyInFlight == up => \A e \in queue : e.ident = ident \/ e.id = InFlight

\* The registrar never answers this, the only writer of its chain, with wrong-parent: a capture
\* it does would be sent again on every pass and never register, nor anything behind it.
NoConflict == ~conflicted

=============================================================================
