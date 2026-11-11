# Operations and feature inventory

## Unreleased 0.5 development implementation status

| Surface | Implemented | Qualification boundary |
| --- | --- | --- |
| Comparison planning | Copy/Move/Update/Missing/Sync/Mirror/Compare proposals, size/time/digest modes, bounded immutable pages, filters and protected exclusions | Preview facts; no native mutation authority |
| Conflict policies | Per-item/selection/subtree/class rules, precedence, newest/size/source/target/keep-both choices, explicit tie handling, zero-length/retention protection | Native tree review freezes rules and manual native names into a revocable receipt; provider refusal remains visible |
| Durable sessions | Baseline codec/checksum, edit/delete classification, metadata conflicts, deletion guards, overlapping-root locks, native verification receipts, durable generation compare-and-swap and recovery | Session commit verifies both roots; a baseline receipt alone never executes a two-way data plan |
| Native two-way execution | One coordinator owns both root locks, frozen inventories, bulk conflict receipts, mixed-direction regular-file operations, protected retention evidence, convergence checks, ledger and baseline commit | Current native scope is ordinary regular files directly below each root; hierarchical convergence remains unavailable; qualification is revision/provider specific |
| Owned journal roots | Asynchronous adopt/provision, private native directory and ancestor ownership, durability barriers, memory-only retain/poll, consumer-bound shared authority and explicit finish/drain | A displayed path never replaces the held root; delayed close errors must be observed before exit |
| Reviewed trees | Native inventory, immutable pages and facts, assessment, receipt-bound execution, stale receipt rejection, pause/resume/cancel and explicit worker drain | Each provider must qualify publication, metadata and source retirement; unsupported primitives cannot become success |
| Retained replacement | Journaled old-target retention and explicit retained names before incoming publication | Requires stable old-object content and an object-bound native rename; unknown coverage refuses replacement |
| Batch rename | Exception-free C jobs, exact native names, duplicate/cycle/collision review, reverse dependency order, one-use approval and bounded verified retry | Windows qualified native handle rename; POSIX source-name mutation remains refused |
| Native Trash/restore | Explicit capability opt-in, private native metadata, live opaque receipt, held original-parent identity and no-overwrite restore | Qualified local Windows NTFS regular files and directories, including volumes without DOS drive letters; other providers remain conditional/refused |
| Preservation | Versioned policy assessment, ordinary-scope native checks, mode/time verification and special-bit stripping | Complete preservation remains unavailable; opaque attributes and unsupported security are refused |
| Job lifecycle | Worker-side setup, cancellation, bounded/coalesced events, retained terminal byte progress, explicit reconciliation outcomes | Cross-platform CI and installed-consumer checks qualify each revision |
| Recovery | Private journal inspection and immutable C summary/pages | Read-only; no automatic replay authority |
| Verified retry/resume | Stable C jobs, fresh one-use review, whole-source digest, explicit read-only prefix candidate, new private staging/journal, independent final content verification, cancellation and worker drain | A new operation; no historical staging adoption or cleanup authority, and no bypass of native publication/metadata qualification |
| Browser models | Optional C++ browser target | Separate from C ABI engine/platform dependencies |

Full ACL/xattr/security replay and complete mixed-direction hierarchical
execution remain delivery gates. The 0.5 root/retry/two-way integration is
under qualification. Implemented interfaces and a passing
planning suite do not establish a platform's mutation capabilities. Consult the
[revision-specific evidence](validation-2026-11-02.md): the macOS strong
publication gate remains open, so its positive copy qualification is failing.

## Coordinator ledger inventory

Linux checks for ledger directory changes with inotify on the held private
root. The watch requires inotify, openat2, and a verified procfs view of the
worker's descriptor table. macOS checks the held directory with kqueue.
These platforms refuse the inventory if the watch cannot be established,
reports a change, or loses coverage. The existing root identity and directory
version checks also apply through the end of the scan.

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

## Qualification and further ABI slices

The remaining slices complete mixed-direction hierarchical execution, native
preservation and cross-platform qualification of root capabilities and verified
prefix resume. Tree/action/session/root/retry APIs carry typed review,
capability, partial/recovery and access outcomes. No interface declaration or
capability-family bit authorizes weakening identity or path-safety rules.
