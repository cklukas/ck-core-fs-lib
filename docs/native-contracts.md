# Native execution contracts

The 0.4 API separates caller-fact previews from native execution. A
`ckfsp_plan` remains a preview only. It cannot be converted into mutation
authority. Native workers retain roots, enumerate exact components, hash
content, freeze their observations, and obtain their own reviewed receipts.
See the [validation record](validation-2026-11-02.md) for tested revisions and
provider limits; an API declaration is not platform qualification.

## Reviewed trees

`ck_fs_tree.h` provides asynchronous native inventory, bounded pages, review
commands, and execution of the exact reviewed plan. Rules carry the plan
generation and explicit scope. Updating a review supersedes older receipts.
Execution revalidates native evidence before mutation; a fresh application of
preferences is not a replacement for the reviewed decisions.

Both sides' observed kind, size, modification time, and precision are returned
with their availability. Comparison keys are lossless internal keys. Use the
native component copy-out API for names; never parse keys or display labels
back into operation addresses. POSIX names retain bytes; Windows names retain
UTF-16 units.

There are at most 32 live tree workers and 4,096 submitted rules per command.
The event ring holds 64 snapshots and reports coalesced snapshots. Polling and
paged item state are authoritative after an event gap. A command's outcome
persists until explicitly acknowledged, and another command is refused while
one is pending or unacknowledged. This protects review and execution outcomes
from event coalescing.

Pause and cancellation are cooperative requests. `pause_requested` records
the request; `paused` means the worker has reached a safe waiting point.
`ckfet_release` requests cancellation and returns without joining. The worker
retains native owners until it stops safely. Legacy `ckfe_job_destroy` still
joins and belongs on a worker/reaper, never a UI event handler.

A terminal tree snapshot records the completed operation protocol, including
required writes and flushes or an explicit failure/recovery outcome. Native
owners can still be closing after that snapshot. Helper processes must poll
`ckfet_worker_drained_v1` until true before releasing the job and exiting. This
nonblocking query becomes true only after the worker's native resources and
admission slot are released; no backend I/O follows it. It does not convert a
failed operation into success or erase retained staging and recovery evidence.

## Retained replacement

The incoming file is copied and its data and requested metadata are verified
before replacement preparation runs. `RetainedTarget` independently hashes
the reviewed old target while holding a qualified writer-exclusion handle.
It durably journals the intent, renames the exact old object to a unique
version name, flushes the namespace, and records completion. The copy worker
then attempts no-replace publication of the incoming file.

The retained object keeps its data streams, security, attributes, and identity
because it is moved on the same filesystem. There is no automatic expiry.
Cancellation, failure, or an uncertain publication never authorizes deletion
of either version. Failure after retention requires reconciliation, including
when a competing object occupies the final name. Retention journals and copy
journals are separate durable evidence; they are not a cross-object atomic
transaction.

The provider must qualify source-object conditional rename and writer
exclusion. A POSIX `stat` followed by a name-based rename does not satisfy that
contract. Neither does an advisory session lock. Unsupported providers refuse
this operation before moving the old target. Provider refusals are limits,
not completed platform implementations.

## Metadata replay

`MetadataReplayPolicy` selects the requested scope, original or current-caller
ownership, and explicit permission to replay privileged security metadata.
`ckfe_copy_options_v2` exposes those choices to C consumers. Permission to
replay is independent of actual OS access; the library never elevates.

Capture, application, and verification operate through held objects. Attribute
names, values, flags, ACLs, and security records are bounded and compared after
application and again before publication. A failed query is not an empty
attribute list. Unknown namespaces, integrity/provider semantics, or missing
rights fail strict preservation. Explicit metadata-loss consent remains
separate and does not qualify the requested preservation scope.

Ordinary scope leaves arbitrary hidden namespaces unknown. Complete scope
requires the provider to establish its stated coverage. Linux unprivileged
attribute enumeration cannot establish absence of arbitrary `trusted.*`
attributes. Inode identity, ctime, hard-link topology, and physical allocation
are distinct from logical metadata replay and must not be reported as copied.

## Durable two-way sessions

`ck_fs_session.h` opens a private coordinator and retains identities and locks
for both roots. Overlapping and nested root sessions cannot bypass locks by
choosing a different pair ID. These locks coordinate library sessions; they do
not exclude unrelated filesystem writers.

The store stages and flushes a generation, publishes a durable intent, installs
the generation, and flushes its parent. It retains prior generation evidence
and recovers a validated interrupted intent. Generation checks compare
the loaded and stored state. Corruption or a missing required baseline remains
a review condition. First-run approval is explicit.

Raw caller-supplied equality updates cannot advance a native C baseline.
Verified sessions issue opaque, session/generation/policy-bound convergence
receipts after native content and required-metadata verification. Commit
rechecks that evidence and consumes the receipt. Skipped or unequal entries
retain old baseline evidence as pending. This does not claim a simultaneous
snapshot of both roots; later changes are detected in the next comparison.

The current native convergence slice covers qualified regular files and
definitive final-component absence. Missing intermediate parents, directory
metadata convergence, links, and other unsupported kinds require their own
native contracts. Do not infer complete two-way tree execution from the durable
store or regular-path receipt APIs.

## Owned journal-root lifecycle

The 0.4 root factory adopts or provisions a private native directory, retains
its native ancestry and performs required durability barriers on its worker.
Only a Ready capability may be shared with operations. The root's displayed
address is a navigation hint; tree operation journals and their consumers
use the same held native owner. A per-journal duplicate is closed independently.

Finishing a root stops new consumer acquisition and waits for existing shared
consumers. Drain consumers first, then finish and drain the root. Poll the
final root outcome for delayed flush/close errors before exit. Cached terminal
tree pages can outlive the tree worker without retaining native root authority.
Provisioning cancellation preserves created evidence rather than attempting
name-based cleanup. See the [C lifecycle contract](c-api.md#owned-journal-roots).

## Action jobs and qualification

`ck_fs_actions.h` defines worker-owned batch rename, native Trash/restore, and
verified recovery jobs. Reviews bind exact names, collision decisions, and
native evidence. Unsupported native facilities never fall back to permanent
deletion or shell commands. Retry eligibility must prove that the failed call
had no ambiguous effect; a generic I/O error is insufficient.

The standalone platform harness pins source and installed-library hashes and
records toolchain, timing, and native fixture outcomes. Native-call acceptance
and deterministic crash-state tests are separate from physical power-loss
qualification. Sanitizers must instrument the entire implementation and use
matching dependency layouts; a mixed-layout crash is not a valid passing gate.

## Hardening work after the integration checkpoint

The native copy protocol closes its writable destination after durable
publication and before completion or any source-removal intent. It caches the
actual committed identity before closing; it never claims a fresh observation
through the closed writer. Final journal close is also fallible. Close errors
require reconciliation and never turn into successful completion. Descriptors
are consumed before close and never retried after EINTR or another ambiguous
close result.

Failure and cancellation also finalize the private data writer and journal
before a terminal execution result is exposed. A child already at a completed
phase is advanced through its stopped parent transitions before its native
owners are released. Finalizers run at most once, including when they throw;
all remaining owned closes are attempted and the first error remains visible.
A finalization failure changes cancellation into a reconciliation result.
Finalization grants no publication, source deletion, or staging-name cleanup
authority.

Journal flush includes both the file and its retained parent directory, so a
successful record does not depend on an unflushed journal entry. Darwin also
requires `F_FULLFSYNC`. Legacy pathname callers must durably provision the
journal root and its ancestors before handing it to the library; the 0.4
capability factory owns those preparation barriers. These calls and fault tests do
not establish physical power-loss qualification.

Linux staging uses `O_TMPFILE` and publishes the held object with a no-replace
hard link. A qualified `/proc/thread-self/fd` route supports unprivileged
publication when the empty-path operation is denied. Anonymous staging has no
filename. Recovery evidence version 6 records that distinction; the retained
name is only a diagnostic hint and is never reopened or deleted. Old evidence
versions remain named and cannot manufacture live creator ownership.

Ordinary named creation is separate from staging. POSIX name-based publication
cannot satisfy the source-identity contract by checking before and after
rename. It is refused rather than silently substituted for held-object
publication. The current macOS provider has no qualified strong publication
implementation; positive macOS copy/execution gates remain open.

Complete metadata capture, application and verification currently refuse
unproved logical-security coverage. A successful ordinary copy is not Complete
preservation. Complete provider qualification requires every requested logical
class, including labels/capabilities, to be known and preserved. Windows
alternate streams, complete security coverage, directory replay, native
two-way composition and verified prefix resume remain active implementation
work. None is qualified merely by its interface or a model test.
