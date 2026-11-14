# Native execution contracts

The native API separates caller-fact previews from native execution. A
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

The unreleased native Tree execution path issues a private seal only from the
accepted immutable review. The seal binds the comparison, metadata policy,
operation ID and genuine held roots. Each mutation obtains a row-specific
permit; caller-authored inventories, native IDs and display paths cannot mint
one. Source metadata is revalidated before staging, target metadata is observed
independently, and directories replay metadata after their children and streams.

Completion evidence becomes available only after final whole-tree verification
and successful native drainage. It retains read-only continuity pins and belongs
on the native worker, including its release. Its context check is memory-only:
it establishes historical membership in this exact Tree/review/row, not current
filesystem equality or permission to advance a two-way baseline. A session must
perform its own fresh native validation and commit protocol. See the
[development validation record](validation-2026-11-03-development.md) for the
qualified Windows scopes and pending combined/platform gates.

## Native archive image writer

The unreleased `NativeArchiveWriteJob` creates and retains its own native stage,
materializes bounded extents and zero gaps, verifies the full image, and journals
no-replace publication. ARW2 records remain descriptive evidence. Its worker-only
lifetime, Root first-error drainage, cancellation and uncertain-publication
outcomes are defined in the [archive writer contract](native-archive-write.md).
Source-volume acquisition, stable C archive APIs, replacement retention and
Tree execution receipts remain separate capabilities.

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

## Proposed CDE entry and replacement contract

**Blocking integration gap; proposal only.** CDE currently pins qualified SDK
0.3 at `3972516`, keeps FS Apply disabled, and uses dtfile's legacy worker-owned
mutation contract. Its local Replace backup is best-effort compatibility
behavior, not durable retention or crash/restart evidence. A local SAME_ENTRY
flag based on resolved pathname equality is a conservative action blocker only.
It is never backend execution authority. This proposal does not add exports,
qualify a provider, or authorize using newer headers with that SDK.

The replacement requires two additive opaque C capabilities. Existing v1
layouts and exports must remain unchanged; exact names and ABI revision remain
subject to implementation and qualification.

| Proposed capability | Backend-owned evidence | Caller-visible result |
| --- | --- | --- |
| Held entry binding and relation job | Genuine held parent, exact native leaf, held object, provider namespace rules, and current binding/continuity checks | Same entry; distinct entries referencing the same object; distinct objects; or Unknown, with a typed reason |
| Reviewed replacement job and receipt | Held source and destination bindings, verified incoming staging owner, old-target retention owner, policy, operation identity, review generation, and durable journals | Reviewable capabilities and consequences; one-use execution receipt; per-row publication, retention and recovery outcomes |

Both jobs perform filesystem work on backend workers. UI calls submit bounded
copied requests or retrieve cached snapshots, pages and exact native components.
Cancellation and release are nonblocking requests; a separate drained query
establishes that native owners and the admission slot have been released. An
owned capability cannot be constructed from caller-authored IDs, hashes, native
paths, or a relation enum. Releasing a handle invalidates further caller use
without abandoning an in-flight native operation.

Relation assessment must distinguish object identity from directory-entry
identity. Two hard links can reference the same object while remaining distinct
entries. Windows case aliases and short names require qualified native namespace
evidence; raw UTF-16 inequality is not proof of distinct entries. Resolved path
equality can refuse an operation but cannot mint a capability. Unknown or
ambiguous parent/leaf continuity stays blocked. A relation snapshot is historical
evidence, not a token authorizing later deletion or replacement.

The backend must enforce the actual mutation through a qualified held-object
boundary after fresh revalidation. A pathname check followed by pathname erase,
rename, or overwrite leaves a race and does not satisfy this contract. A
provider without the required primitive must refuse the affected operation;
advisory locks, timestamps or another successful stat do not supply it.

The review freezes job identity, row IDs, generation, source and destination
observations, direction, exact native naming choices, metadata policy, retention
policy and expected consequences. Only an accepted worker review issues a
one-use receipt. A new review invalidates older receipts. The backend rejects
stale, foreign, unresolved or already-consumed receipts before mutation. A bulk
preference applies only to its reviewed scope; a newly discovered conflict needs
a new review. Command outcomes remain identifiable until acknowledged even when
progress events coalesce.

Replacement uses the existing retained-target protocol: verify incoming content
and required metadata, durably prepare retention, move the exact old target to
its reviewed unique version name, flush and record that transition, then attempt
no-replace publication of the incoming object. Never overwrite an intervening
entry. Incoming success requires verified publication and every required file,
journal and namespace durability barrier and fallible close. The old version
remains retained after success; this proposal grants no automatic expiry or
backup deletion. Any later retirement requires its own explicit policy and live
native authority. Source retirement is likewise a separate reviewed operation.

Snapshots must distinguish no mutation, old target retained, publication
attempted, publication confirmed, verified completion, cancellation, partial
work, and reconciliation required. These are separate facts, not a single
success flag. Once retention or publication has occurred, cancellation cannot
pretend that nothing changed. A failure or uncertain publication preserves the
retained object and evidence; it does not authorize path-based rollback or
deletion. Native first-error evidence must survive allocation failure, late
finalizers and cancellation. Pending diagnostic publication is provisional,
never a successful terminal result or an immutable placeholder error.

Durable receipts record exact native components, observed object identities and
versions, requested/achieved preservation, transition ordering, journal IDs and
retained-version outcomes. Persisted evidence supports bounded read-only restart
inspection. It does not recreate a live entry binding, grant cleanup authority,
or authorize automatic mutation replay. Cross-object retention/publication is
not advertised as an atomic transaction or a simultaneous filesystem snapshot.

CDE may replace its compatibility path only after the following admission gates:

1. Implement the opaque bindings, relation worker and replacement receipt bridge
   using genuine native providers and bounded handle/memory admission, including
   retained streams and overlapping ownership graphs.
2. Qualify positive supported operations and explicit refusals on each admitted
   provider. Cover hard links, native aliases, parent/leaf replacement and
   reparenting, reparse/mount transitions, concurrent writers, security changes,
   long DOS/UNC paths and exact UTF-16 names where applicable.
3. Exercise stale/foreign/replayed receipts, review replacement, cancellation at
   every transition, disk-full, persistent allocation failure, consumed-close
   errors, partial publication and crash/restart inspection. Independently verify
   that original, incoming, competing and retained objects have the promised
   contents and identities, and that no unreviewed object was erased.
4. Build a coherent installed SDK and independent C consumer; verify headers,
   exports, lifetime/drained semantics and matching normal/sanitizer matrices.
   Publish the exact admitted revision and provider limitations to CDE before
   changing its dependency pin or enabling any previously blocked command.

Until those gates pass, the compatibility path remains explicitly separate and
FS Apply remains disabled. API declarations, relation labels, focused passing
tests, or the existence of newer C++ internals do not close this integration gap.

## Proposed C atomic file writer

**Integration requirement; no exports or SDK admission yet.** CDE needs to
replace its per-directory icon-position file without truncating the previous
valid file before the replacement is ready. Neither frozen FS 0.3 nor the
current C action API provides an atomic replacement writer. The action API's
no-overwrite contract and the archive writer's no-replace publication must not
be presented as this capability.

The proposed additive `ckfaw_*_v1` family uses a backend worker and a genuine
held parent with an exact native leaf. Existing C layouts and exports remain
unchanged. Requests copy or retain bounded inputs before returning and specify
the destination expectation, mode/owner/ACL policy, content limits, and required
file/parent durability. Unsupported preservation or publication requirements
block admission instead of being silently weakened.

A caller-supplied C producer runs on the worker and writes through an opaque
bounded sink. The backend owns the actual temporary object and handles checked
short writes, EINTR and native errors. The sink is valid only during its active
callback on that worker. The callback performs no UI work, does not join or
destroy its job, and returns structured status; no C++ exception crosses the
C boundary. Exposing a writable temporary descriptor would let callers close
or replace backend ownership, so that is not the proposed default interface.

The required protocol is exclusive collision-resistant creation without
symlink following, explicit security preparation, complete checked writing,
requested file durability and verification, atomic publication, required parent
durability, and all fallible finalizers. Random names are collision avoidance,
not proof of ownership. A pathname check followed by pathname rename does not
satisfy the stronger held-entry publication requirement.

| Result boundary | Required evidence |
| --- | --- |
| Pre-commit failure or cancellation | Previous destination remains intact; report any temporary effect and attempt cleanup only with live native authority |
| Publication attempted | Record confirmed, refused or uncertain publication independently from requested/achieved durability |
| Post-publication failure | Report reconciliation or unknown durability; retain evidence and never claim that the previous file was restored |
| Verified completion | Required content, security, publication, durability and finalization steps all succeeded |
| Release/cancellation | Nonblocking request; caller callback/context lifetime extends until the separate drained query confirms completion |

Snapshots and errors must be allocation-independent POD with version/size
validation, stage, domain, native errno/Win32/NTSTATUS, and effect/durability
facts. The first native error survives later callback, allocation, close and
cancellation failures. Cancellation after publication cannot erase evidence or
skip the required completion protocol. Persisted names, IDs and hashes never
authorize restart cleanup or automatic mutation replay.

Provider admission distinguishes atomic namespace replacement, durable
publication and identity-bound conditional replacement. Local filesystem names
alone do not prove those properties; remote/UNC durability and sharing semantics
require their own qualification. This writer depends on the held-entry and
publication guarantees described above and remains a blocking implementation
gap where those guarantees are unavailable.

Qualification must cover positive admitted providers, short writes/EINTR,
callback failure, disk-full, cancellation at every transition, metadata failure,
parent flush and consumed-close errors, concurrent entry/security replacement,
symlinks/reparse points, resource bounds, exact native names and long DOS/UNC
paths where admitted. Independently verify old/new/competing objects and
pre-commit preservation. CDE keeps feedback and cancellation at its UI boundary
and must not consume this proposed API with its frozen SDK.

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

The unreleased 0.5 `ckfss_two_way_*` companion owns one mixed-direction executor rather
than composing two opposing copy jobs. It freezes both inventories, metadata
policy, baseline generation and conflict decisions into native review receipts.
The first scope covers ordinary regular files directly below each root. It
performs actual qualified copies and retained replacements/deletions, then
fresh convergence verification before baseline commit. Unsupported structural
changes remain explicit blocked rows.

An operation ledger records the execution and convergence intent. Required
journal flushes and fallible closes precede baseline compare-and-swap; sealing
and restart recovery follow it. Partial, skipped, cancelled or uncertain data
execution cannot silently advance the baseline. Retained artifacts remain
visible protected evidence, identified by exact native components and fresh
observations. A data filename prefix never hides user files, and recovered
identities never become live cleanup authority.

## Owned journal-root lifecycle

The 0.4 root factory adopts or provisions a private native directory, retains
its native ancestry and performs required durability barriers on its worker.
Only a Ready capability may be shared with operations. The root's displayed
address is a navigation hint; operation journals and baseline/ledger consumers
use the same held native owner. A per-journal duplicate is closed independently.

Finishing a root stops new consumer acquisition and waits for existing shared
consumers. Drain consumers first, then finish and drain the root. Poll the
final root outcome for delayed flush/close errors before exit. Cached terminal
tree pages can outlive the tree worker without retaining native root authority.
Provisioning cancellation preserves created evidence rather than attempting
name-based cleanup. See the [C lifecycle contract](c-api.md#owned-journal-roots).

Scan guards certify genuine native providers and held ancestry in both
directions. A multiply linked regular file also requires a fresh bounded native
private-state identity walk. An ordinary external hardlink remains usable; a
name selecting private state cannot enter the mutation plan. Incomplete walks,
unknown identities, mount/reparse boundaries and changed namespace bookends
are refusals. The proof is neither a cached inode set nor a namespace lease.
Its native duplicates are consumed once; close errors reach the Root's fixed
failure latch before error-message allocation.

### Windows journal temporary close errors

Temporary Windows journal handles now preserve a real `CloseHandle` failure in
an active `MetadataCaptureCleanupScope` before diagnostic allocation. The first
native error wins over later injected or cleanup failures. A consumed handle
is never closed again: a reused numeric value must not become cleanup authority.
This deleter does not invent a Root binding outside an active cleanup scope.

The dedicated regression configuration rebuilds the SDK and client with one
uniform `CK_FS_NATIVE_CLOSE_TEST_HOOKS` definition. From an MSVC developer
PowerShell 7 shell, with source and all temporary outputs on `V:`, select a
fresh task directory and the actual provider explicitly:

```powershell
if (-not [IO.Directory]::Exists('V:\')) { throw 'V: unavailable' }
$task = Join-Path 'V:\tmp' ('journal-close-' + [Guid]::NewGuid().ToString('N'))
foreach ($name in 'TEMP','TMP','TMPDIR') {
    [Environment]::SetEnvironmentVariable($name, $task, 'Process')
}
[IO.Directory]::CreateDirectory($task) | Out-Null
$fixture = Join-Path $task 'fixtures'
[IO.Directory]::CreateDirectory($fixture) | Out-Null
$provider = [IO.DriveInfo]::new('V:\').DriveFormat
if ($provider -cnotin @('NTFS','ReFS')) { throw 'Unsupported fixture provider' }
$env:CK_FS_REQUIRE_V_DEV_DRIVE = '1'
cmake -S . -B (Join-Path $task 'build') -G Ninja `
  -DCMAKE_BUILD_TYPE=Debug '-DCMAKE_CXX_FLAGS=/GR /EHsc /utf-8' `
  -DBUILD_TESTING=ON -DCK_CORE_FS_TEST_NATIVE_CLOSE_HOOKS=OFF `
  -DCK_CORE_FS_TEST_JOURNAL_TEMPORARY_CLEANUP=ON `
  "-DCK_CORE_FS_NATIVE_TEST_ROOT=$fixture" "-DCK_CORE_FS_ARCHIVE_TEST_FS=$provider" `
  "-DCK_CORE_FS_METADATA_TARGET_NATIVE_FS=$provider"
if ($LASTEXITCODE -ne 0) { throw 'Configure failed' }
cmake --build (Join-Path $task 'build') `
  --target ck_fs_journal_temporary_cleanup_windows_tests --parallel 1
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
ctest --test-dir (Join-Path $task 'build') `
  -R '^journal_temporary_cleanup_windows_' --parallel 1 --output-on-failure --no-tests=error
```

Every native case independently checks its held provider. Ordinary and data-long
variants cover control, real protected-handle failure, consumed-close failure,
and both failure modes under persistent C++ allocation denial. The qualified
NTFS and ReFS configurations passed 10 cases each, 624 checks in total. Data
parents exceeded 340 UTF-16 units; their child temporary environments were
shorter. These are local journal-close regressions, not whole-suite, UNC, raw
UTF-16-name, sanitizer, resource-graph or inherited-long-environment qualification.
The separate native-close suite switch stays off; no legacy IAT fixture is
executed by this dedicated target.

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

Recovery evidence version 7 records the original source leaf for
copy-based moves. It preserves exact POSIX bytes or Windows UTF-16 units
alongside the source parent and object identities. A tree move records the
root leaf even after its live source handles have been released. These
fields support read-only reconciliation. Source retirement requires fresh
native authority and a stability proof. Versions 1–6 remain readable.

Ordinary named creation is separate from staging. POSIX name-based publication
cannot satisfy the source-identity contract by checking before and after
rename. It is refused rather than silently substituted for held-object
publication. The current macOS provider has no qualified strong publication
implementation; positive macOS copy/execution gates remain open.

Complete metadata capture, application and verification refuse unproved
logical-security coverage. A successful ordinary copy does not establish
Complete preservation. Complete provider qualification requires every requested
logical class, including labels/capabilities, to be known and preserved.
Development cohorts have exercised Windows alternate streams, Full Original
and CurrentCaller security/ownership replay, and postorder directory metadata
on NTFS and ReFS. The later combined cohort still has native failures under
investigation, including ReFS CurrentCaller ancestry validation. The Linux Full
issuer is limited to the qualified no-birthtime ext4/security environment.
These scoped results, exact revisions and open gates are recorded in the
[development validation record](validation-2026-11-03-development.md).

Native two-way composition and verified prefix resume have development
interfaces and focused native evidence; remaining integration qualification is
separate. A pending journal Root first-error writer revokes completion even
before its diagnostic tuple is readable. Retry finalizers drain once without
waiting inside callbacks. The outer worker retains the Root and waits for
memory-only error publication before exposing final completion or worker drain.
Neither an interface nor a model test qualifies native execution.
