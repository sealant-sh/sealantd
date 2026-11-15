---------------------------- MODULE CaptureQueue ----------------------------
(***************************************************************************)
(* The capture staging queue (crates/sealant-capture/src/ship.rs) with its  *)
(* writers: the engine's snaps (enqueue, coalesce, the journaled restage of *)
(* a hoist or a repair), the shipper (claim, upload, register, ack) and a   *)
(* process crash at any step, after which the daemon reopens its staging    *)
(* (Staging::open finishes a committed restage) and resumes the queue       *)
(* (CaptureEngine::resume_queue). README.md beside this file says what each *)
(* action stands for in the code, the bounds and what is left out.          *)
(*                                                                           *)
(* A snap is a token 1..MaxSnaps: the work it saved. A capture (a queue     *)
(* entry, a chain link) carries the tokens of every snap folded into it.    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    MaxSnaps,     \* snaps the engine takes
    MaxCrashes,   \* process crashes
    MaxRefusals,  \* registrar refusals (422 missing-objects), each answered by a repair
    Mutants       \* {} is the code; README.md lists the deliberate breaks

Classes == {"small", "bulk"}
Snaps == 1..MaxSnaps
\* Every manifest the engine writes gets a fresh id: a snap writes one, a hoist two, a repair one.
MaxId == 2 * MaxSnaps + MaxRefusals
Ids == 1..MaxId
NoId == 0

Entry == [id: Ids, n: 1..MaxId, parent: Ids \cup {NoId}, content: SUBSET Snaps, class: Classes]

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
    \* Counters and ghosts.
    snaps, crashes, refusals,
    staged,     \* tokens of every snap that reached the queue (or a committed journal)
    acked,      \* ids the shipper removed from the queue by an ack
    conflicted  \* the registrar answered wrong-parent

vars == <<queue, jpending, journal, repairReq, chain, up, eng, jstep, prev, ship, nextId,
          snaps, crashes, refusals, staged, acked, conflicted>>

NoEntry == [id |-> NoId, n |-> 0, parent |-> NoId, content |-> {}, class |-> "small"]
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
    /\ prev = [id |-> NoId, n |-> 0]
    /\ ship = Idle
    /\ nextId = 1
    /\ snaps = 0
    /\ crashes = 0
    /\ refusals = 0
    /\ staged = {}
    /\ acked = {}
    /\ conflicted = FALSE

----------------------------------------------------------------------------
\* The engine.

\* A snap waits for a pending repair (snap_preemptible runs the repair first) and for a restage.
EngineFree == up /\ eng = "idle" /\ ~jpending /\ ~(\E e \in queue : e.id = repairReq)

\* Staging::coalescible: the newest queued capture, of the snap's class, that the shipper is not on.
CanCoalesce(class) ==
    /\ queue # {}
    /\ Newest.class = class
    /\ ("coalesce-in-flight" \in Mutants \/ Newest.id # InFlight)

\* CaptureEngine::hoist_target: a small snap goes ahead of the newest queued capture when it is a
\* bulk one the shipper is not on and the engine staged it last.
CanHoist(class) ==
    /\ class = "small"
    /\ queue # {}
    /\ Newest.class = "bulk"
    /\ Newest.id # InFlight
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
                      content |-> old.content \cup {s}, class |-> class]
                ELSE [id |-> nextId, n |-> prev.n + 1, parent |-> prev.id,
                      content |-> {s}, class |-> class]
       IN /\ queue' = Put(queue, e)
          /\ prev' = [id |-> e.id, n |-> e.n]
          /\ snaps' = s
          /\ nextId' = nextId + 1
          /\ staged' = staged \cup {s}
    /\ UNCHANGED <<jpending, journal, repairReq, chain, up, eng, jstep, ship, crashes, refusals,
                   acked, conflicted>>

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
           fold == below # NoEntry /\ below.class = "small" /\ below.id # InFlight
           small == IF fold
                    THEN [id |-> nextId, n |-> below.n, parent |-> below.parent,
                          content |-> below.content \cup {s}, class |-> "small"]
                    ELSE [id |-> nextId, n |-> b.n, parent |-> b.parent,
                          content |-> {s}, class |-> "small"]
           moved == [id |-> nextId + 1, n |-> small.n + 1, parent |-> small.id,
                     content |-> b.content, class |-> "bulk"]
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
    /\ UNCHANGED <<queue, repairReq, chain, up, ship, crashes, refusals, acked, conflicted>>

\* CaptureEngine::repair: the refused capture rebuilt from disk at its n with its parent, every
\* capture staged after it folded in, as one journaled restage.
Repair ==
    /\ up /\ eng = "idle" /\ ~jpending
    /\ \E r \in queue :
        /\ r.id = repairReq
        /\ LET followers == {f \in queue : f.n > r.n}
               rebuilt == [id |-> nextId, n |-> r.n, parent |-> r.parent,
                           content |-> UNION {f.content : f \in followers \cup {r}},
                           class |-> r.class]
           IN /\ journal' = [write |-> <<rebuilt>>, sup |-> followers \cup {r}, repair |-> TRUE]
              /\ prev' = [id |-> rebuilt.id, n |-> rebuilt.n]
    /\ jpending' = ("no-journal" \notin Mutants)
    /\ eng' = "restage"
    /\ jstep' = 1
    /\ nextId' = nextId + 1
    /\ UNCHANGED <<queue, repairReq, chain, up, ship, snaps, crashes, refusals, staged, acked,
                   conflicted>>

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
                   crashes, refusals, staged, acked, conflicted>>

ApplyRemove ==
    /\ Applying
    /\ jstep = Len(journal.write) + 1
    /\ LET written == {journal.write[i].n : i \in DOMAIN journal.write}
           gone == {x.n : x \in journal.sup} \ written
       IN queue' = {x \in queue : x.n \notin gone}
    /\ jstep' = jstep + 1
    /\ UNCHANGED <<jpending, journal, repairReq, chain, up, eng, prev, ship, nextId, snaps,
                   crashes, refusals, staged, acked, conflicted>>

ApplyDone ==
    /\ Applying
    /\ jstep = Len(journal.write) + 2
    /\ jpending' = FALSE
    /\ journal' = NoJournal
    /\ jstep' = 1
    /\ eng' = IF up /\ journal.repair THEN "clear" ELSE "idle"
    /\ UNCHANGED <<queue, repairReq, chain, up, prev, ship, nextId, snaps, crashes, refusals,
                   staged, acked, conflicted>>

\* The repair is done: repair.json removed.
ClearRepair ==
    /\ up /\ eng = "clear"
    /\ repairReq' = NoId
    /\ eng' = "idle"
    /\ UNCHANGED <<queue, jpending, journal, chain, up, jstep, prev, ship, nextId, snaps,
                   crashes, refusals, staged, acked, conflicted>>

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
                   crashes, refusals, staged, acked, conflicted>>

Claim ==
    /\ up /\ ship.st = "idle"
    /\ eng # "restage" /\ ~jpending
    /\ queue # {}
    /\ Oldest.id # repairReq
    /\ ship' = [st |-> "claimed", e |-> Oldest]
    /\ UNCHANGED <<queue, jpending, journal, repairReq, chain, up, eng, jstep, prev, nextId,
                   snaps, crashes, refusals, staged, acked, conflicted>>

\* Every object the entry lists is put (and acked as uploaded): idempotent, so not modelled further.
Upload ==
    /\ up /\ ship.st = "claimed"
    /\ ship' = [ship EXCEPT !.st = "uploaded"]
    /\ UNCHANGED <<queue, jpending, journal, repairReq, chain, up, eng, jstep, prev, nextId,
                   snaps, crashes, refusals, staged, acked, conflicted>>

\* capture.register, the registrar's CAS: the next n on the head is appended; the head itself sent
\* again is a lost ack, answered as success; anything else is wrong-parent. Or 422: refused, and a
\* repair is asked for.
Register ==
    /\ up /\ ship.st = "uploaded"
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
                   staged, acked>>

\* Staging::ack: the queue file at the entry's n removed (then its objects swept), then released.
Ack ==
    /\ up
    /\ \/ ship.st = "registered"
       \/ "ack-before-register" \in Mutants /\ ship.st = "uploaded"
    /\ queue' = {x \in queue : x.n # ship.e.n}
    /\ acked' = acked \cup {ship.e.id}
    /\ ship' = Idle
    /\ UNCHANGED <<jpending, journal, repairReq, chain, up, eng, jstep, prev, nextId, snaps,
                   crashes, refusals, staged, conflicted>>

----------------------------------------------------------------------------
\* Crash and restart.

Crash ==
    /\ crashes < MaxCrashes
    /\ up' = FALSE
    /\ eng' = "idle"
    /\ jstep' = 1
    /\ ship' = Idle
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<queue, jpending, journal, repairReq, chain, prev, nextId, snaps, refusals,
                   staged, acked, conflicted>>

\* Staging::open has finished any committed restage (ApplyWrite.. with up = FALSE); the engine
\* opens on the registered head and resume_queue acks a queued capture the registrar holds as its
\* head (registered, its ack lost) before anything snaps (SLNT-1009). Then it continues from the
\* queue. "resume-keeps-registered" is the code before SLNT-1009: the capture stays queued.
Restart ==
    /\ ~up /\ ~jpending
    /\ up' = TRUE
    /\ LET q == IF "resume-keeps-registered" \in Mutants
                THEN queue
                ELSE {x \in queue : ~(x.id = HeadId /\ x.n = HeadN)}
       IN /\ queue' = q
          /\ prev' = ResumeFrom(q)
          /\ acked' = acked \cup {x.id : x \in queue \ q}
    /\ UNCHANGED <<jpending, journal, repairReq, chain, eng, jstep, ship, nextId, snaps, crashes,
                   refusals, staged, conflicted>>

----------------------------------------------------------------------------
Next ==
    \/ \E c \in Classes : SnapPlain(c)
    \/ SnapHoist
    \/ Repair
    \/ ApplyWrite \/ ApplyRemove \/ ApplyDone \/ ClearRepair
    \/ ClearStaleRepair \/ Claim \/ Upload \/ Register \/ Ack
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
        \A e \in queue :
            \/ e.n = HeadN /\ e.id = HeadId
            \/ e.n = HeadN + 1 /\ e.parent = HeadId
            \/ e.n > HeadN + 1 /\ \E f \in queue : f.n = e.n - 1 /\ f.id = e.parent

\* I4: a queue file leaves by an ack only once the registrar holds its capture.
AckedAreRegistered == acked \subseteq ChainIds

\* I5: the entry the shipper holds is never superseded under it.
ClaimedNeverSuperseded ==
    ship.st # "idle" => (\E e \in queue : e.id = ship.e.id) \/ ship.e.id \in ChainIds

\* The registrar never answers this, the only writer of its chain, with wrong-parent: a capture
\* it does would be sent again on every pass and never register, nor anything behind it.
NoConflict == ~conflicted

=============================================================================
