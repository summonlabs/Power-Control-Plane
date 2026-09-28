# Design notes

## Systems boundary

Power Control Plane owns the facility-wide authority layer for electrical operating
state. It decides:

* which electrical operating mode is in force and which mode transitions are legal;
* which switching or control actions are permitted, and under which evidence,
  capacity, interlock, obligation, permission, and policy conditions;
* which power-policy decision is authoritative for the current generation;
* which attempted action must be refused as stale, unsafe, unauthorized, or
  inconsistent.

It does not own, and does not reimplement: electrical topology, per-feed eligibility,
PDU device lifecycle, UPS device lifecycle, generator lifecycle, load-shedding
execution, energy accounting, capacity computation, facility placement, or black
start. Those facts arrive as typed `EvidenceRef` values that carry the producing
runtime's identity, generation, revision, controller epoch, controller incarnation,
and content digest.

The library never talks to equipment. Every physical consequence leaves through an
`ActuationAdapter` supplied by the embedding process, and the repository embeds no
endpoint, credential, or protocol.

## Deterministic validation precedence

Refusals are primary-coded. The same invalid request always reports the same first
failure, evaluated in this order:

1. structural validation (bounds, identifiers, declared demand)
2. idempotent replay of an already committed operation
3. controller authority (epoch, incarnation) for mutations
4. planned-against generation, publication revision, policy revision
5. evidence binding and runtime freshness
6. safety interlocks
7. protected obligations
8. capacity commitments
9. permission grants
10. ordered power policy

Steps 2 and 3 are ordered so a retry of an accepted operation returns the committed
result before a now-stale generation check can reject it. Step 6 precedes step 10 so
no policy rule can outrank a safety interlock.

## Authority, epochs, incarnations, and fencing

Four identities are kept distinct:

* `StoreIncarnation` - a 128-bit identity generated once when a store is created.
* `ControllerEpoch` - a monotonically increasing writer-authority counter, advanced
  by exactly one on every acquisition.
* `ControllerIncarnation` - a 128-bit identity of one writer session inside an epoch.
* `ControlGeneration` and `StateRevision` - the authoritative electrical generation
  and the publication revision.

`ControlGeneration` advances only when the electrical operating state changes (a mode
transition). `StateRevision` advances on every publication. Both are needed: a
permission's lifetime is bounded in both, and "which electrical generation is
authoritative" is a different question from "how many metadata updates have been
published".

Writer authority is an operating-system lock on `pcp.lock`: a file opened with no
sharing on Windows, an exclusive advisory lock on POSIX. The kernel releases it when
the owning process terminates for any reason, so a crashed writer never leaves a store
permanently locked.

Holding the lock is necessary but not sufficient. A writer publishes through a
`WriterLease` that carries its epoch, its incarnation, the store incarnation, and a
process-local token. Every mutation is validated against the current authority before
it is applied, so a lease whose epoch has been superseded is refused with a typed
`stale_authority` outcome even if the same process still holds some lease object.

The authority marker is the rollback fence. It records the highest revision ever
published. A head marker naming an older revision than the fence is refused as a
rollback rather than silently adopted. The fence is advanced after the head marker is
committed, so a crash between the two leaves the fence behind the head, which is safe.

## Concurrency model and lock order

Two locks exist in the store, with a fixed order:

```
DurableStore::authority_mutex   (outer)
    -> DurableStore::state_mutex (shared, leaf)
```

* `state_mutex` is a shared mutex guarding the published head and the immutable cached
  state pointer. Readers take it shared; publication takes it exclusively only for the
  final pointer swap, which performs no I/O and calls no user code.
* `authority_mutex` guards the writer lease and the whole publication sequence. It is
  deliberately held across store I/O, because the epoch advance and the durable marker
  update must be atomic against other in-process writers. It is never held across
  adapter callbacks, user code, or blocking waits.
* No path takes `state_mutex` and then `authority_mutex`.

The engine adds `Runtime::commit_mutex`, which serializes the whole
read-validate-commit sequence of every mutation. Without it, two threads could both
validate against the same revision and the loser would have to be refused inside the
store instead of by the documented precedence chain. Mutation verbs that perform their
own evaluation (`authorize_action`, `request_mode_transition`) hold it across the
evaluation and the commit; `commit_record` takes it and delegates to an unlocked body
so the mutex is never re-entered.

Runtime evidence freshness is guarded by `Runtime::mutex`, a leaf lock that is only
ever held for a value copy.

Ownership audit performed by inspection:

* no read-lock to write-lock upgrade exists: `state_mutex` is either taken shared for
  the whole read or taken exclusively for the pointer swap, never upgraded;
* no write lock is held while calling code that reacquires it: the only nested
  acquisition is `authority_mutex` then `state_mutex`, which matches the documented
  order;
* no mutex is re-entered: `commit_record` splits into a locking wrapper and an unlocked
  body precisely so that the verbs that already hold `commit_mutex` can call the body;
* the publication hook is invoked inside the writer critical section, which is a
  deliberate invariant, and a re-entrant call from the hook is refused rather than
  served;
* shutdown (`close`) takes `authority_mutex` only, and releases the operating-system
  lock before returning, so no waiter can be blocked by a closing store;
* readers never block on a publication in progress: the head pointer swap happens after
  the head marker is durable.

## State semantics

* Unknown, unavailable, unsupported, stale, denied, unsafe, and zero are distinct
  states. Missing evidence never becomes zero or "safe".
* A refusal produces a typed outcome plus a machine-readable explanation naming the
  exact obligation, interlock, evidence source, permission, or policy rule responsible,
  together with the authoritative generation and the planned-against generation.
* `evaluate_action` performs the whole precedence chain without mutating anything: it
  consumes no permission, creates no attempt, and advances no revision.
* Interlocks fail closed: an engaged or unknown blocking or critical interlock blocks
  every action in scope, and an interlock whose scope could not be determined covers
  everything rather than nothing.
* Protected obligations are preserved by every transition. An obligation can only
  become suspended through an explicit authority-bound `SuspensionRecord`, and an
  active continuity-required obligation cannot be removed at all.
* A permission is a bounded grant, never a boolean: kinds, targets, generation
  lifetime, revision lifetime, policy revision, evidence binding, and a use budget.
  Any drift makes it unusable, and a revoked, superseded, or exhausted grant can never
  be replayed.
* Authorization, issued command, acknowledgement, observed effect, and verified effect
  are five separate states, each published as its own authoritative revision. A
  verification report produced by the adapter that acknowledged the command is refused
  as not independent.

## Idempotency and retention

Every mutation may carry an `IdempotencyKey`. A committed operation is recorded in a
bounded index inside the authoritative state, and the replay check runs before any
staleness check, so a retry of a lost response returns the recorded result even though
the generation has moved on. A denied or indeterminate operation is not recorded, so a
retry is judged afresh.

Retention semantics: the index is bounded by `Limits::max_replay_records` and attempts
by `Limits::max_attempts`. When a bound is exceeded, the oldest published operation
record and the oldest attempt are retired in the same publication that adds the newest.
Eviction order is by publication revision, which is deterministic and reproducible.
After an entry is evicted, a retry with that key is treated as a new operation and is
judged entirely by the ordinary pipeline. Retention bounds are therefore an operational
sizing decision, not a safety property: an operator who needs a longer replay window
raises the bound.

## Recovery and revalidation

Freshness is runtime state, never persisted. A reopened store reports every bound
evidence reference as not revalidated, and every evidence-dependent decision is
refused until an explicit revalidation publishes a current binding. Recovery therefore
never promotes persisted dynamic evidence to fresh.
