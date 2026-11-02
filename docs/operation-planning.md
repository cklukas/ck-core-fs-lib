# Declarative operation model

The shared library is the policy and execution basis for dtfile, ckUtilities,
CDE, and other frontends. A frontend may choose labels, key bindings, dialogs,
and presentation, but it must not implement a second comparison or mutation
engine.

## Execution pipeline

Every tree operation follows one worker-owned sequence:

1. Inventory the source and destination using held identities, bounded pages,
   explicit link and filesystem-boundary policies, and typed unavailable
   observations.
2. Build a non-mutating plan. Each row receives a stable identity, an action,
   a reason, source/destination observations, protection flags, and a decision
   token. Unknown, unreadable, changed, or failed observations cannot produce
   an `identical` decision or a destination deletion.
3. Present the plan for review. Conflict and loss decisions are scoped to this
   plan and are never inferred from a second scan or from display text.
   Normal changes follow the selected operation profile; a user can review a
   representative conflict and apply a reusable rule to matching rows, a subtree
   or the job. See [conflict resolution](conflict-resolution.md).
4. Execute only after revalidating the same identities, policies, and decision
   token. A changed plan returns to review; it does not silently re-plan.
5. Publish through journaled staging, verify the published identity/content,
   and perform source cleanup only after the durable commit boundary.
6. Expose a bounded terminal summary and recoverable journal state for every
   completion, cancellation, partial result, failure, or reconciliation case.

## Action profiles

The planner will expose these explicit profiles; similar shell commands are
not interchangeable shortcuts:

| Profile | Default behavior | Destructive review |
| --- | --- | --- |
| Copy | Add source objects without replacing an existing destination | Existing conflicts only |
| Safe Move | Verified copy/publication or native move, then source retirement | Source removal after commit |
| Update | Add missing objects and replace only when source is newer | Conflicts and metadata loss |
| Copy missing only | Add source-only objects; never replace destination objects | None for protected counterparts |
| One-way Sync | Explicit source → destination reconciliation | Destination changes and conflicts |
| Mirror | One-way sync plus destination-only removal | Every deletion class separately reviewable |
| Compare-only | Produce the plan and differences, never mutate | None |
| Dry-run | Execute planning and validation phases only | None |
| Batch rename | Preview collisions, then apply identity-checked renames | Collision and overwrite policy |

One-way comparison supports quick size+mtime, size-only, and complete-content
comparison. Timestamp precision and observed skew are explicit inputs; the
planner never invents DST or clock forgiveness. Equal size is not equal
content. Content digests require a complete, stable read.

Include/exclude rules cover names, folders, object types, dates/ages, sizes,
recursion depth, filesystem boundaries, and link traversal. Exclusions protect
destination counterparts from mirror deletion by default. Root escapes,
source/target overlap, case/normalization collisions, and stale decision
tokens are rejected.

## Planned API slices

The public C ABI will grow in this order, with C++ policy types underneath:

1. **Preservation policy and capability inventory.** Replace the global loss
   boolean internally with a versioned policy describing ordinary
   permissions/timestamps, ownership semantics, ACL/security xattrs/labels,
   provider metadata, links, and storage representation. Providers advertise
   qualified support; unsupported or denied classes become typed review items.
2. **Single-object and tree inventory.** Add bounded, cancellable source and
   destination pages with known flags, stable held identities, link policy,
   mkdir policy, filesystem-boundary policy, and exact metadata observations.
3. **Preview plan.** Add opaque plan handles and per-row decisions for source
   only, destination only, source newer, destination newer, size/content
   differences, protected entries, conflicts, and unknowns. Include/exclude
   rules and comparison mode are serialized into the plan identity.
4. **Review and conflict receipts.** Add typed per-item and all-matching
   decisions (replace, skip, keep-both, rename, continue with listed loss),
   each bound to the plan and job. Mirror deletions require their own receipt.
5. **Journaled tree execution.** Add recursive copy/update/sync/mirror jobs with
   bounded concurrency, retry/backoff limits, staging, complete-read
   verification, identity revalidation, safe publication, and source cleanup
   only after commit.
6. **Events, recovery, and adapters.** Add bounded event draining, aggregate
   progress with known flags, durable resume/reconciliation inspection, Trash /
   restore, permanent delete, and provider capability adapters. Two-way sync
   requires a persistent baseline/conflict model and will not be inferred from
   mtimes.

The first gate is strict metadata-preserving regular copy. Tree planning and
execution are not routed through CDE until that gate and its installed C
consumer tests qualify on POSIX and Windows.

## Frontend boundary

CDE/dtfile owns operation setup, review dialogs, conflict presentation,
progress rendering, status messages, and result summaries. The library owns
classification, reasons, identity and policy validation, mutation ordering,
metadata preservation, journals, retries, cancellation, and recovery. No
frontend may shell out to Robocopy, rsync, Commander, or another tool as the
operation engine; those tools are comparison references only.
