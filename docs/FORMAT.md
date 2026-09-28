# Durable store format

This document is the normative description of the on-disk format written by
Power Control Plane 1.0.0. All integers are little-endian. There is no padding, no
alignment, and no platform-dependent field. Text fields are UTF-8/ASCII byte
sequences with a 32-bit length prefix inside canonical payloads, and fixed-width
zero-padded fields inside the fixed-size records described here.

## Directory layout

```
<store root>/
  pcp.lock              operating-system writer lock file (contents unused)
  pcp-authority.bin     authority marker: rollback fence and controller epoch
  pcp-head.bin          authoritative head marker; naming a generation is the commit point
  state-<20 digits>.bin one published, checksummed state generation per commit
  staging/              staging area for the in-flight publication only
```

Every name is fixed by the library. An operator never invents one, and the library
refuses to read a name that does not match the documented pattern.

## Common record rules

* A record begins with an 8-byte ASCII magic, then a 32-bit format version, then a
  32-bit declared record size. The declared size is compared with the actual size
  before any field is trusted.
* A fixed-size record carries a trailing 32-byte SHA-256 seal over the preceding
  body. A variable-size record carries the same seal over everything before it.
* A file whose size does not match its declared size, whose magic or version is
  unknown, whose seal does not verify, or whose declared lengths disagree with the
  bytes present is refused with `ErrorCode::corrupt_store` or
  `ErrorCode::unsupported_format`. Nothing is repaired and nothing is guessed.
* Files are read only after their size has been compared with an explicit bound, so
  an oversized or hostile file is refused without being read into memory.

## Authority marker (pcp-authority.bin)

Fixed 256-byte record: 224-byte body plus a 32-byte seal over the body.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | magic `PCPAUTH1` |
| 8 | 4 | format version (1) |
| 12 | 4 | record size (256) |
| 16 | 16 | store incarnation (high, low) |
| 32 | 8 | current controller epoch |
| 40 | 16 | current controller incarnation (high, low) |
| 56 | 8 | highest published revision (rollback fence) |
| 64 | 8 | highest published generation |
| 72 | 8 | writer process id (diagnostic only) |
| 80 | 144 | reserved, zero |
| 224 | 32 | SHA-256 seal over bytes 0..223 |

## Head marker (pcp-head.bin)

Fixed 288-byte record: 256-byte body plus a 32-byte seal.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | magic `PCPHEAD1` |
| 8 | 4 | format version (1) |
| 12 | 4 | record size (288) |
| 16 | 16 | store incarnation (high, low) |
| 32 | 8 | control generation |
| 40 | 8 | publication revision |
| 48 | 8 | canonical payload bytes |
| 56 | 32 | canonical state digest |
| 88 | 8 | logical tick |
| 96 | 4 | state file name length (1..96) |
| 100 | 96 | state file name, zero padded |
| 196 | 60 | reserved, zero |
| 256 | 32 | SHA-256 seal over bytes 0..255 |

## State generation (state-<revision>.bin)

Variable-size record: 96-byte header, canonical state payload, 32-byte seal.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | magic `PCPGEN01` |
| 8 | 4 | format version (1) |
| 12 | 4 | record size (header + payload + seal) |
| 16 | 8 | control generation |
| 24 | 8 | publication revision |
| 32 | 16 | store incarnation (high, low) |
| 48 | 8 | canonical payload bytes |
| 56 | 32 | canonical state digest |
| 88 | 8 | logical tick |
| 96 | n | canonical state payload |
| 96+n | 32 | SHA-256 seal over bytes 0..(95+n) |

The canonical state digest is `SHA-256("pcp/state-digest/v1" || 0x00 || payload)`, a
domain-separated hash so that a digest computed for another purpose over identical
bytes cannot collide with a state digest.

## Canonical state payload

The payload is a deterministic encoding of the whole authoritative state:

1. 32-bit state encoding version (1)
2. facility identity (bounded text)
3. store incarnation (high, low)
4. control generation, publication revision, policy revision, logical tick
5. operating mode ordinal
6. power policy: policy revision, then rules sorted by (order, identity)
7. evidence binding: references sorted by source identity, each with source, kind,
   generation, revision, controller epoch, controller incarnation, content digest
8. interlocks, protected obligations, capacity commitments, permissions, and
   attempts, each sorted by identity
9. committed-operation index, sorted by idempotency key
10. operating mode history, in publication order
11. transition log, in publication order, each entry carrying its resulting
   generation and revision, the idempotency key it was committed under, the digest of
   the state it started from, the logical tick, and the canonical transition payload
12. identity allocators, pruning counters

Because every collection has a canonical order and no timestamp, memory address,
process identity, or random value is included, two logically identical states always
produce byte-identical payloads. The one intentionally non-derived field is the store
incarnation, which is generated once when a store is created and is part of the
store identity.

## Publication protocol

The exact ordered stages are the `CommitStage` enumeration:

1. `plan` - the engine builds a candidate state from the authoritative state.
2. `validate` - the engine validates the request and applies the transition to the
   candidate.
3. `reserve generation` - the candidate revision and generation are checked to be
   exactly the successors of the current head.
4. `staging_written` - the whole generation image is written to
   `staging/state-<revision>.bin.tmp` with `CREATE_NEW`.
5. `staging_flushed` - the staging file is flushed to durable storage
   (`FlushFileBuffers` on Windows, `fsync` on POSIX).
6. `staging_read_back_verified` - the staging file is read back and compared byte for
   byte with what was written.
7. `generation_published` - the staging file is atomically renamed to
   `state-<revision>.bin`.
8. `head_committed` - the head marker is written to staging, flushed, read back,
   verified, and atomically renamed over `pcp-head.bin`. **This is the commit point.**
9. `authority_marked` - the authority marker's rollback fence is advanced.
10. `residue_retired` - staging files and generations beyond the retention window
    are removed.

## Recovery

On open the store:

* verifies the authority marker, refusing when it is missing, malformed, or fails its
  seal, unless the store is being created for the first time;
* refuses when the head marker is missing but the authority fence records a published
  state, because that would mean silently emptying a store;
* refuses when the head marker names a revision older than the authority fence,
  because that is a rollback;
* verifies the generation the head names, including its seal, its declared sizes, its
  incarnation, and that its decoded state matches the revision and generation the head
  names;
* retires staging residue and any generation newer than the head as residue, never
  adopting it;
* retires generations beyond the configured retention window;
* reports what it did in a `StoreOpenReport`.

Adoption is all-or-nothing: exactly one whole verified generation is adopted, or the
store refuses to open. Partial generations are never stitched together.
