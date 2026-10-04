# Power Control Plane

Power Control Plane is the facility-wide authority layer for electrical operating
state. It answers one question:

> Which facility electrical operating state and control authority are valid now, which
> actions are permitted under the current topology, capacity, interlock, obligation,
> and policy evidence, and which attempted actions must be refused as stale, unsafe,
> unauthorized, or inconsistent?

It is a C++20 library, an administration tool, and a versioned CMake package. It has no
third-party dependencies: the core uses the C++ standard library plus narrow
operating-system primitives for the writer lock and durable file publication.

## Systems boundary

**This runtime owns:** the authoritative facility electrical control model; the
operating mode and the mode transition table; safety interlocks as fail-closed facts;
protected obligations and capacity commitments as external authority-bound references;
switching and control permission grants bounded in scope, generation, and lifetime;
deterministic ordered power-policy evaluation with a complete explanation trace; the
authorization-to-verified-effect attempt lifecycle; and the durable, integrity-checked
persistence of all of it.

**This runtime does not own, and does not reimplement:** electrical topology, per-feed
eligibility rules, PDU device lifecycle, UPS lifecycle, generator lifecycle,
load-shedding execution, energy accounting, capacity computation, facility placement,
or black start. Those facts are consumed as typed evidence references that carry the
producing runtime's identity, generation, revision, controller epoch, controller
incarnation, and content digest. This runtime never models a cold-start sequence, a
dead-bus energization order, or a cranking path.

The library never talks to equipment. Every physical consequence leaves through an
`ActuationAdapter` supplied by the embedding process. There is no embedded
endpoint, credential, or protocol in this repository.

## Architecture

```
include/power_control_plane/       public headers
  ids.hpp            strongly typed identities: epoch, incarnation, generation,
                     revision, attempt, permission, evidence generation/revision
  checked.hpp        checked arithmetic; authoritative counters never wrap
  digest.hpp         SHA-256 and the 32-byte Digest value
  canonical.hpp      deterministic length-prefixed little-endian encoding
  evidence.hpp       typed references to adjacent DCCP runtimes
  mode.hpp           operating modes and the mode transition table
  interlock.hpp      fail-closed safety interlocks
  obligation.hpp     protected obligations, suspensions, capacity commitments
  policy.hpp         ordered policy rules
  permission.hpp     bounded control permissions
  action.hpp         action intents and the authority they were planned against
  decision.hpp       typed outcomes with machine-readable explanations
  attempt.hpp        authorization, issue, acknowledgement, effect, verification
  state.hpp          the authoritative facility state, read-only in public
  transition.hpp     the single mutation path and the transition log
  store.hpp          durable store, writer lease, commit stages, recovery
  engine.hpp         ControlPlane: reads, writer authority, mutation verbs, actuation
  adapter.hpp        the actuation boundary and a deterministic simulator
  snapshot.hpp       immutable reader views
  report.hpp         commit, integrity, replay, and revalidation reports
src/                 implementation; src/detail holds the OS abstractions and the
                     library-internal mutable access to FacilityState
tools/pcp_cli.cpp    the pcp administration tool
examples/            four runnable lifecycle examples
bench/               the completed-operation benchmark
tests/               the proof-obligation test suite and its independent-process probe
downstream/consumer/ an out-of-tree find_package consumer
docs/                store format and design notes
```

The library is exported as the namespaced CMake target
`PowerControlPlane::power_control_plane`.

## Authority, generation, and fencing

Five identities that are usually collapsed into one integer are kept distinct:

| Identity | Meaning |
| --- | --- |
| `StoreIncarnation` | 128-bit identity of one durable store, generated once at creation |
| `ControllerEpoch` | monotonic writer-authority counter, advanced by one per acquisition |
| `ControllerIncarnation` | 128-bit identity of one writer session inside an epoch |
| `ControlGeneration` | the authoritative facility electrical control generation |
| `StateRevision` | the authoritative publication revision |

`ControlGeneration` advances only when the electrical operating state changes, which
is a mode transition. `StateRevision` advances on every publication. A permission is
bounded in both.

Writer authority is a real operating-system lock (a file opened with no sharing on
Windows, an exclusive advisory lock on POSIX) that the kernel releases when the owning
process dies. Holding it is necessary but not sufficient: every mutation presents a
`WriterLease` carrying its epoch, incarnation, store incarnation, and process-local
token, and is refused with a typed `stale_authority` outcome once a successor has taken
authority.

The authority marker is a rollback fence recording the highest revision ever published.
A head marker older than the fence is refused rather than silently adopted.

## Deterministic validation precedence

Refusals are primary-coded. The same invalid request always reports the same first
failure, in this order:

1. structural validation
2. idempotent replay of an already committed operation
3. controller authority (epoch and incarnation)
4. planned-against generation, revision, and policy revision
5. evidence binding and runtime freshness
6. safety interlocks
7. protected obligations
8. capacity commitments
9. permission grants
10. ordered power policy

Step 2 precedes step 4 so a retry of an accepted operation returns the committed result
before a now-stale generation check can reject it. Step 6 precedes step 10 so no policy
rule can outrank a safety interlock.

## State semantics

A decision is never a boolean. Every decision names the authoritative generation and
policy revision it was evaluated against, the evidence binding digest that was current,
the generation the request was planned against, and an ordered explanation trace naming
the exact obligation, interlock, evidence source, permission, or policy rule
responsible.

* Interlocks fail closed. An engaged **or unknown** blocking or critical interlock
  blocks every action in scope, and an interlock whose scope could not be determined
  covers everything rather than nothing. No policy rule can clear, weaken, or outrank
  one.
* Unknown, unavailable, unsupported, stale, denied, unsafe, and zero stay distinct.
  A missing capacity commitment produces an explicit indeterminate outcome; it is never
  treated as zero demand.
* A denied or indeterminate operation changes no authoritative state at all: the
  revision, the generation, the attempt set, and the permission use count are
  untouched, and nothing is recorded for replay.
* `evaluate_action` runs the whole precedence chain without mutating anything: it
  consumes no permission, creates no attempt, and advances no revision.
* Authorization, issued command, acknowledgement, observed effect, and verified effect
  are five separate published facts. A verification report produced by the adapter that
  acknowledged the command is refused as not independent.
* Protected obligations are preserved by every transition. An obligation becomes
  suspended only through an explicit authority-bound suspension record, and an active
  continuity-required obligation cannot be removed at all.

## Persistence and recovery

The store is a versioned, integrity-checked binary format with an explicit magic, a
format version, fixed-size seal-checked head and authority records, and one checksummed
generation file per publication. The complete format is specified in
[docs/FORMAT.md](docs/FORMAT.md).

The publication protocol is staged and observable:

```
plan -> validate -> reserve generation -> write staging -> flush durable content
     -> read back and verify -> atomically publish generation
     -> commit authoritative head marker  <-- the commit point
     -> advance the rollback fence -> retire residue
```

On open the store adopts exactly one whole verified generation or refuses. A generation
file that the head marker does not name is residue from an interrupted publication and
is retired, never adopted. A missing head with a non-zero fence, a fence ahead of the
head, a failed seal, a declared length that disagrees with the bytes present, or an
oversized file all cause a refusal with a typed error.

Recovery never makes persisted dynamic evidence fresh. Evidence freshness is runtime
state: a reopened store reports every bound reference as not revalidated, and every
evidence-dependent decision is refused until an explicit revalidation publishes a
current binding.

## Building

Requirements: CMake 3.21 or newer and a C++20 compiler. The exercised platform is
Windows with MSVC (Visual Studio 2022, toolset 19.44).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Build options:

| Option | Default | Meaning |
| --- | --- | --- |
| `POWER_CONTROL_PLANE_BUILD_TESTS` | ON (top level) | build the proof-obligation test suite |
| `POWER_CONTROL_PLANE_BUILD_EXAMPLES` | ON (top level) | build and register the four examples as tests |
| `POWER_CONTROL_PLANE_BUILD_BENCHMARKS` | ON (top level) | build the benchmark |
| `POWER_CONTROL_PLANE_BUILD_TOOLS` | ON (top level) | build the `pcp` administration tool |
| `POWER_CONTROL_PLANE_WARNINGS_AS_ERRORS` | ON | first-party warnings are errors |
| `POWER_CONTROL_PLANE_ENABLE_ASAN` | OFF | build first-party targets with AddressSanitizer |
| `POWER_CONTROL_PLANE_DOWNSTREAM_PREFIX` | empty | install prefix that enables the out-of-tree consumer test |

## Installing and consuming the package

```sh
cmake --install build --prefix /some/prefix
cmake -S downstream/consumer -B consumer-build -DCMAKE_PREFIX_PATH=/some/prefix
cmake --build consumer-build
cmake --build consumer-build --target run_consumer
```

A consumer writes:

```cmake
find_package(PowerControlPlane 1.0 REQUIRED)
target_link_libraries(my_target PRIVATE PowerControlPlane::power_control_plane)
```

## Command line tool

`pcp` is a thin driver: every verb calls the same `ControlPlane` API an embedding
process would call, so there is no path that bypasses the policy and interlock engine.
Exit codes are `0` accepted or replayed, `1` usage or input error, `2` refused by the
control plane, and `3` store or integrity failure.

```
pcp --store <path> [--read-only] [--retain N] <verb> [options]

inspection
  version | state | mode | authority | interlocks | obligations | permissions
  attempts | evidence | revalidation | history | store | verify [--replay]
  policy | policy-eval | evaluate

administration (takes writer authority automatically)
  init --facility <id> [--mode <mode>] [--evidence <spec>]...
  mode set <target> --authority <ref> [--suspend <obligation>:<authority>]...
  authority acquire | authority release
  revalidate --evidence <spec>...
  policy set --rule "<order>|<effect>|<condition>|<argument>|<explanation>" ...
  interlocks set <id> --source <src> --severity <s> --state <st> [--kind <k>]...
                  [--target <t>]... [--explain <text>]     |    interlocks clear <id>
  obligations set <id> --source <src> --authority <ref> ...  |    obligations remove <id>
  commitments set <id> --source <src> --authority <ref> --kw <n> [--target <t>]...
  permissions grant --kind <k>... [--target <t>]... [--uses N] [--generations N]
                    [--revisions N] [--authority <ref>]
  permissions revoke <id> | permissions retire <id> <state>
  attempt --action <id> --kind <k> --target <t> [--load-kw N]
          [--adapter <behaviour>] [--verifier <behaviour>]
```

Two behaviours are worth calling out because they are the engine showing through the
tool:

* `--evidence <spec>` asserts that the named external evidence references are current.
  The assertion is itself a mutation, so the tool publishes a revalidation and then
  runs the verb with the asserted evidence in force for that process. Without it, every
  evidence-dependent verb is refused, because a fresh process has no revalidated
  evidence. The tool never invents freshness on the operator's behalf.
* `--key <hex>` sets an explicit idempotency key. The default is derived from the verb
  and its arguments, so re-running the exact same command replays the committed result
  rather than executing twice.

An evidence spec is
`source:kind:generation:revision:epoch:incarnation-hex:digest-hex`.

## Examples

| Example | What it demonstrates |
| --- | --- |
| `pcp_example_lifecycle` | clean startup, policy installation, revalidation, a mode transition that preserves a continuity-required obligation, an action refused by that obligation, an authorized action, and store verification |
| `pcp_example_stale_authority` | an interlock refusal no permissive policy can override, an idempotent replay of a lost response, an exhausted permission, a superseded writer epoch, and a stale control generation |
| `pcp_example_crash_recovery` | a child process terminating inside the publication after the generation file is published but before the head marker is committed, then reopen, orphan retirement, stale evidence, revalidation, and verification |
| `pcp_example_adapter_simulation` | authorization, issued command, acknowledgement, observed effect, and verified effect as five separate states across five scripted adapter behaviours |

All examples run as tests. The crash-recovery example starts a real second process and
terminates it with `std::_Exit`, which ends the process immediately without running
destructors or entering any error-reporting path.

## Validation performed

Everything below was executed on the machine described in the benchmark section.

* **Release and Debug builds.** `/W4 /WX /permissive- /utf-8 /Zc:__cplusplus` for the
  library, the tool, the examples, the benchmark, and every test target. Both
  configurations build warning-free and pass the full suite.
* **Eighteen registered CTest cases**: four examples plus fourteen proof-obligation
  suites covering identity and canonical encoding, model rules and fail-closed
  semantics, authority and precedence, idempotency and retention, the attempt
  lifecycle, durable persistence and malformed-input rejection, path safety, recovery,
  deterministic replay, concurrency, adversarial and boundary-shaped input, seeded
  randomized state-machine invariants, real multiprocess and crash injection, and the
  command line tool. No test carries a timeout.
* **Multiprocess proof.** A live writer refuses a second process with
  `lock_unavailable`; a process that dies while holding writer authority releases the
  lock to the kernel and the successor's epoch advances; a child that cannot publish
  with a superseded epoch is refused; and process death is injected at each of the seven
  durable publication stages, after which the store reopens with exactly one whole
  verified generation and takes new work.
* **Deterministic replay proof.** For every retained publication pair, the logged
  transition payload is applied to the older published state and the result must be
  byte-identical to the newer published state. This is checked after every crash stage
  and by the `verify --replay` verb.
* **Adversarial input proof.** Corrupted head, corrupted generation, truncated head,
  oversized head, unknown magic, unknown format version, missing authority marker,
  missing head with a non-existent fence, an orphan generation, staging residue, a
  directory where a file is required, a traversal segment in the store root, an empty
  or control-character-bearing root, an overlong root, and a directory link substituted
  for the store root are each refused with a typed error. Every single-byte corruption
  of a canonical state payload either fails to decode or decodes to a different state.
  An empty transition payload is refused for every one of the twenty transition kinds
  and leaves the state byte-identical; an oversized transition payload is refused
  before it is applied; a canonical field declaring a four-gigabyte length is refused
  by the bound check without being read; twelve open-commit-close cycles leave no
  staging residue and no orphan generation; a refused request is never recorded for
  replay; and a bound of zero refuses rather than wrapping.
* **Randomized proof.** Seeded state-machine sequences drive real verbs and check
  invariants after every step; a failure reports the seed, and the same seed reproduces
  the same final revision, generation, mode, and collection sizes.
* **Installed-package and downstream proof.** The package installs to a clean prefix,
  and an independent out-of-tree consumer configures with `find_package`, builds, and
  runs the full lifecycle against the installed package.

Hardware validation was **not** performed and is not claimed. All actuation evidence in
this repository is produced by a deterministic simulator and is labelled SYNTHETIC.

## Benchmarks

`pcp_bench` measures completed operations only. Every timed mutation includes
validation, canonical encoding, the staging write, the required durable flush, read-back
verification, the atomic generation publish, the authoritative head-marker commit, the
rollback-fence advance, and residue retirement. Nothing times enqueue or submission
latency and calls it completion.

```sh
build/bench/pcp_bench --root bench-store --scale 1
```

Methodology: single run per scenario at scale 1, no warm-up, wall time measured with
`std::chrono::steady_clock` around the whole loop of completed operations, throughput
reported as operations divided by wall time. Every result is labelled REAL: the durable
work is performed against the host file system. The actuation evidence inside the
attempt-lifecycle scenario is SYNTHETIC, because it comes from the deterministic
simulator. The benchmark verifies the store before it finishes, prints the final state
digest, and removes its store root.

Recorded on the reference host (Windows, NTFS, MSVC 19.44, Release, scale 1):

| Scenario | Label | Completed | Wall | Per operation | Throughput |
| --- | --- | --- | --- | --- | --- |
| canonical encode + SHA-256 | REAL | 2000 ops | 0.032 s | 16.15 us/op | 61927 ops/s |
| evaluate_action (no publish) | REAL | 5000 ops | 0.076 s | 15.15 us/op | 65991 ops/s |
| authorize_action + durable commit | REAL | 200 ops | 4.494 s | 22470 us/op | 44.5 ops/s |
| mode transition + durable commit | REAL | 200 ops | 5.358 s | 26790 us/op | 37.3 ops/s |
| attempt lifecycle (6 commits) | REAL | 40 ops | 4.050 s | 101261 us/op | 9.9 ops/s |
| verify_store integrity check | REAL | 50 ops | 0.067 s | 1337 us/op | 748 ops/s |
| verify_replay deterministic replay | REAL | 20 ops | 0.698 s | 34883 us/op | 28.7 ops/s |

The durable cost is dominated by the required durable flushes: three per publication
(staging content, head marker, authority fence) plus read-back verification. Facility
electrical control is not a high-frequency operation, and the protocol is deliberately
weighted towards provable recovery rather than throughput.

## Remaining limitations

* **Windows/MSVC is the only verified platform.** POSIX branches for the lock, file
  I/O, directory listing, and process handling are implemented and structurally sound
  but were not built or executed in this environment. Portable is not claimed as proven.
* **No hardware validation.** The adapter boundary, the simulator, and the safety
  semantics are validated; nothing has been connected to electrical equipment.
* **The retry window is bounded by configuration.** The committed-operation index and
  the attempt set are bounded, and an operator who needs a longer replay window must
  raise `Limits::max_replay_records` or `Limits::max_attempts`.
* **The rollback fence trusts the authority marker.** An attacker who can rewrite both
  the head marker and the authority marker consistently is outside the documented trust
  model; the fence detects a rollback of the store directory, not a full adversarial
  rewrite of it.
* **Policy is installed through the API or the rule syntax of the tool.** There is no
  separate policy authoring language or configuration file format.
* **Mode transitions are facility-wide.** Per-bus or per-feed operating modes belong to
  the adjacent runtimes and are consumed here as scope on evidence and permissions.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
