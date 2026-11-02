# Operations and feature inventory

## Available in the first C ABI revision

- Engine creation and deterministic API/state names.
- Absolute UTF-8 path opening and Windows UTF-16 path opening.
- Directory handles with explicit final-link policy.
- Entry opening relative to a held directory handle.
- Structured metadata: object kind, logical size, allocated size, link count,
  and native identity fields when available.
- Journal-root preparation and generated operation identity.
- Regular-file copy with identity-bound source/destination handles.
- Regular-file move with same-filesystem and cross-filesystem handling supplied
  by the native operation engine.
- Bounded I/O chunks, short-read/short-write handling, cancellation polling,
  and metadata-loss policy.
- Nonblocking job start, snapshot polling, cooperative cancellation, and
  join-before-destroy lifetime semantics.
- Byte progress snapshots with an explicit known-total flag; no guessed
  percentage is exposed when the source size is not qualified.
- Terminal states for completion, cancellation, failure, changed source,
  and recovery required.

## Native backend capabilities used by the frontend

- Directory cursors and identity-aware child lookup.
- Recursive inventory with link/reparse-point policy and cycle protection.
- Native Windows directory walking without legacy `MAX_PATH` assumptions.
- File metadata, security, links, streams, storage, integrity, fscrypt, and
  platform capability observations.
- Operation planning, conflict projections, consent, commit, journal files,
  recovery evidence, and cross-filesystem move retention.
- Recursive deletion engine and recovery primitives, awaiting their stable C
  ABI adapter.

## Planned ABI slices

The next slices add typed conflict decisions, recursive copy, rename, delete,
Trash/capability adapters, progress-event draining, recovery inspection and
reconciliation, and explicit `WaitingForDecision`, `Cancelling`, `Partial`,
`Unsupported`, and `Denied` state transitions. These are API work items, not
permissions to weaken the identity or path-safety rules above.
