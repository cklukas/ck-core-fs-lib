# C API

The entry header is [`include/ck_file_engine.h`](../include/ck_file_engine.h).
`ck_fs_tree.h`, `ck_fs_actions.h`, `ck_fs_session.h`, `ck_fs_journal_root.h`,
and `ck_fs_retry.h` expose native reviewed execution, action jobs, durable
sessions, owned journal roots and verified copy retry. All headers are usable from C and C++ and contain no C++ types, exceptions, STL
containers, or frontend types.

## Ownership

`ckfe_engine_create`, `ckfe_directory_open_*`, `ckfe_entry_open_*`, and job
start functions return opaque handles owned by the caller. Destroy functions
release them. Legacy `ckfe_job_destroy` requests cancellation and joins its
worker; call it on a worker/reaper. Tree release and action-job release are
nonblocking: the worker retains its owners until it stops safely. Session
open/verify/commit/close operations belong on a filesystem worker.

For helper-process shutdown, keep the tree job alive and poll
`ckfet_worker_drained_v1` until it returns OK with a nonzero result before
release and process exit. A terminal snapshot can precede native-owner
destruction. Drained is a lifetime guarantee, not an operation-success result.

Initialize a `ckfe_error` with `ckfe_error_init`. Every API that accepts an
error output clears it on entry and overwrites it on failure; call
`ckfe_error_free` when done. Failed calls reset non-null output handles and
metadata to their empty values. The operation
string is allocated by the library and must never be freed with a language
runtime allocator.

## Jobs

The unreleased 0.5 development interface exposes ABI minor 5. Existing handles
and snapshot layouts are unchanged. The shared-library identity includes 0.5
(`libck-core-fs-lib.0.5` on Unix and `ck-core-fs-lib-0.5.dll` on Windows), so
an older binary cannot satisfy dependencies on the new exports. Use the
installed CMake package and verify the actual runtime version before use.

Start functions return quickly. `CKFE_API_OK` means a non-null job handle was
created; a rejected operation returns `CKFE_API_OPERATION_UNAVAILABLE` and a
structured `ckfe_error`, never a null job with an OK status. Polling is
nonblocking and returns a snapshot
with explicit `total_*_known` flags. Call `ckfe_job_cancel` for cooperative
cancellation and continue polling until a terminal state is observed. The
frontend owns presentation and the user's choices. The backend assesses
conflict rules and binds execution to reviewed evidence; it never calls back
into the UI.

For regular-file copy, `processed_bytes` is updated from the bounded native
copy state machine and `total_bytes_known` is true only when a stable source
size observation is available. A frontend must display indeterminate progress
when the flag is false.

The regular-file operation also requires an explicit metadata-loss policy. A
request with `allow_metadata_loss` set to zero is rejected or finishes with a
structured `ProviderReviewRequired` failure when the platform cannot preserve
all metadata that the operation contract requires. The C ABI does not silently
turn unsupported security or provider metadata into a successful copy. A
caller that explicitly accepts the declared loss may set the flag to nonzero.

`ckfe_job_start_copy_regular_v1` accepts an exact version/size options object.
Complete metadata scope requires qualified full replay. Ordinary
caller-visible scope is an explicit narrower request: mode 0777, atime/mtime,
and new-object effective UID/GID ownership (including correction of setgid-parent
group inheritance). Source ownership, birth/ctime, special bits, arbitrary
hidden xattrs and physical allocation identity are outside this scope. Native
replay captures and verifies visible xattr/EA values and ACL/security records.
Privileged labels/capabilities and special bits require explicit opt-in through
`ckfe_copy_options_v2`, independently of native access rights. Unknown coverage,
additional streams, integrity/provider semantics, sparse/flagged representations,
or missing rights remain refusals where not qualified. Exact timestamp/mode verification is required;
there is no precision or umask fallback.

`ckfe_job_get_preservation_report_v1` reports requested scope, achieved fields,
explicit exclusions, unknowns and provider qualification without requiring UI
code to parse diagnostic strings. Achieved fields are published only after
successful completion. Ordinary copying never implicitly authorizes source
deletion or retention of an old destination with excluded metadata.
Successful loss-consenting jobs report individually verified basic fields but
leave provider qualification Unknown and do not claim caller UID/GID application:
those paths bypass inventory and ownership setup. Complete scope cannot become
qualified through loss consent. Ordinary scope is qualified only when its
required native inventory, staging and prepublication checks actually pass.

Native journal setup and operation construction run on the job worker. Once
arguments are accepted, a start may return OK and later report a typed terminal
capability/access/setup failure. Polling and event draining must continue until
the terminal state. Snapshot events have a fixed 64-entry ring with explicit
coalescing counts; polling retains the final state independently of draining.

`ckfe_recovery_open_utf8` is a filesystem-worker read of a bounded private
journal. Immutable summary/page calls report durable states and review actions,
including untrusted tails/evidence. Inspection never authorizes automatic
replay, deletion or source retirement.

`ck_fs_tree.h` starts native inventory on held roots and returns bounded
immutable preview facts and native names. Review produces a matching receipt;
execution revalidates the frozen evidence. Each command outcome persists until
acknowledged. Rules, manual native names, per-row eligibility, rejection reasons,
retained names and recovery identifiers are backend results. Unknown or failed
inventory cannot become `identical` or authorize mirror deletion. See
[native contracts](native-contracts.md) for lifetime and platform limits.

Compare accepts no journal root and a zero operation ID. Mutation-only
namespace fields are ignored in that profile; rules remain descriptive and
every executable row is Report. A Compare receipt cannot authorize Copy or
Sync. Other profiles still require their mutation journal and operation ID.

`ck_fs_actions.h` provides batch rename, native Trash and receipt-bound restore.
Use preview row reasons to disable unavailable commands. Renames reject cycles
and occupied destinations and order chains from their free end. Trash requires
explicit native capability consent and never falls back to permanent deletion.
Restore accepts a live opaque receipt and a freshly held original parent; it
never imports authority from serialized Trash metadata. Destroying a job is a
nonblocking cancellation/release. A terminal action state follows journal
finalization and release of the operation's native input owners; separately
retained Trash receipts keep read-only identity pins until their own disposal.
`ckfea_trash_receipt_get_kind` distinguishes regular files and directories
without changing the existing receipt-info layout. A directory move carries its
whole native object; it does not recursively erase or report an invented byte
total. Restore removes the verified native `$I` entry even while an old receipt
still pins its identity. Original-path text can use an extended volume GUID
when the local volume has no DOS letter; that text never selects the restore
destination.

`ck_fs_session.h` provides worker-only durable baseline sessions and verified
commit receipts. Open retains both root locks, including overlap protection;
commit is generation-checked and crash recovery preserves uncertain evidence.
The `ckfss_two_way_*` companion composes native inventory, frozen conflict
rules, mixed-direction execution, convergence verification and baseline commit.
Its current native scope is ordinary regular files directly below each root;
nested trees and structural directory metadata remain unavailable. Bulk rules
use backend facts and an opaque assessed receipt. A baseline receipt alone
never authorizes data execution.

## Owned journal roots

Initialize `ckfjr_options_v1`, retain a held parent directory and select
`ADOPT_HELD`, `ADOPT_CHILD` or `PROVISION_CHILD`. Start returns promptly;
preparation, privacy/ancestry checks and durability barriers run on the owned
worker. Only `CKFJR_READY` permits acquiring a consumer. Provisioning preserves
a failed or cancelled created directory for explicit recovery; it never removes
an object through a name that may have changed.

`ckfjr_start_v1` returning Busy or InvalidArgument with a null output is a
pre-worker admission/argument failure: no preparation or provisioning ran.
OutOfMemory and Exception do not establish that guarantee. A failure after
worker creation requests stop and joins before returning, but may already have
created recovery evidence. A null output alone never authorizes cleanup.

Pass the root to the additive tree/action/session entry point rather than
reopening its displayed address. The capability owns the native directory;
pathname fields are navigation hints only where that API permits them. Retain
and poll are memory-only. A consumer finishes its own journal duplicates and
releases its shared root owner; it does not finish the common root.

For shutdown, cancel or complete each consumer and observe its worker drain.
Then request `ckfjr_finish_v1`, continue polling until root worker drain, and
inspect the final root snapshot for delayed flush/close errors before release
or process exit. A terminal tree handle may remain alive for cached pages after
its worker has drained; that cached handle does not keep the native root open.
Root drain is a lifetime guarantee and does not imply operation success.

Mutating tree inventory must isolate its active journal Root from both scan
roots. Native ancestry and per-entry identity checks cover the actual held
objects, including separate engine instances; a displayed address is not
scope evidence. Proven overlap or unqualified alias topology is refused with
Unsupported / Adapter / PlanTopologyUnsafe before a mutation plan is accepted.
Unrelated directories with the same basename remain ordinary input. A changed
Root membership instead retains its Changed/MetadataChanged or stale-plan
outcome. Legacy tree addresses are adopted once on the worker and must already
be private; rejection does not secure an overlapping user folder by chmod.

The scope proof requires a qualified native filesystem provider as well as a
native cursor. A stacked or network provider can translate identities and hide
its backing ancestry. Linux scope certification is limited to direct ext4,
XFS and Btrfs, and macOS to local APFS. Unsupported providers and per-entry
mount boundaries are refused before review. A bind-mounted private journal
file is therefore not treated as an ordinary file outside its Root.

Directory ancestry alone cannot exclude a regular file with multiple names.
Such a file additionally requires a fresh bounded native identity inventory of
the private Root, including nested directories. The inventory reads names and
identities, not file contents. Native source and namespace bookends must remain
valid; incomplete, inaccessible, changed, mounted or reparse inventories cannot
produce an accepted plan. Ordinary hardlinks outside private state remain valid
input. No timestamp-keyed membership cache survives the assessment.

This isolation applies to the passed Root capability. It is not a global
active-root registry. Cross-process protection for cooperating rename/Trash
clients requires the separate native namespace-lease execution gate; external
writers still require native revalidation and recovery handling.

## Verified retry and prefix resume

`ck_fs_retry.h` starts a new reviewed operation from held source/destination
owners, bounded original journal evidence and an explicitly selected read-only
candidate. No filename or deletion authority is imported from recovery text.
The attempt uses a fresh operation ID, fresh journal and new private staging
object. Its one-use review binds the whole source SHA-256, strict metadata,
candidate prefix and original journal bytes.

The worker verifies the prefix against the frozen source, copies it into new
staging, then reads the remaining source. Both the assembled digest and an
independent staging reread must match the frozen whole-source digest before
metadata and no-replace publication. A candidate EOF cannot end the full copy.
The original candidate, source and journal are preserved.

`ckfer_start_with_journal_roots_v1` retains two READY capabilities. Initialize
both pathname fields to empty and supply the required exact journal names.
Drain retry jobs before finishing their shared roots. A genuine pending Root
failure writer prevents final completion and worker drain until its first native
error is published. Waiting happens on the retry worker after callbacks and
native finalizers return; UI polling remains memory-only. Repeated finalization
reads cached diagnostics and never retries an already consumed native close.
Snapshots retain native
error scalars and journal finalization errors; release never joins. These
contracts do not turn an unsupported publisher or metadata provider into a
successful resume.

## Comparison and policy headers

`ck_fs_policy.h` contains fixed-width versioned preservation dispositions and
inventory assessments. It assesses explicitly supplied worker evidence; it does
not invent provider capabilities or authorize replay.

`ck_fs_plan.h` exposes opaque immutable comparison previews from bounded
caller-supplied facts. It provides summary/page/path access and whole-input
revalidation against plan-local tokens. It distinguishes incomplete inventory,
quick size/time equality and complete stable digests. Input facts cannot become
native operation authority through this interface. `ck_fs_tree.h` owns a separate
native inventory and receipt path; it does not promote caller-fact previews.

## Native encoding

On POSIX, `_utf8` path/name inputs are byte-preserving component strings: the
library does not validate or re-encode them. The native filesystem may reject a
byte sequence, as APFS does for invalid UTF-8; that native error is preserved.
On Windows, `_utf8` inputs are decoded as UTF-8 and invalid
sequences are reported as Unsupported/UnrepresentableName. Windows callers that need exact
UTF-16 names can use the UTF-16 entry points. The native adapter performs the
final filesystem operation through its wide/native boundary; the C API's UTF-8
conversion is not a permission to use narrow Win32 I/O.

## Unreleased 0.5 cached Tree diagnostics

`ck_fs_diagnostics.h` requires ABI minor 5 or later. Initialize a
`ckfet_failure_details_v1` and call `ckfet_get_failure_details_v1` to copy one
cached publication: failure state/domain/code, bounded operation tag, sequence,
plan generation and current row. Correlate separate snapshot/detail reads only
when their sequence numbers match. After worker drain, cached details remain
readable without retaining the native Root or reopening any object.

The getter performs no allocation, filesystem I/O or callback. Invalid version,
size, reserved fields or null arguments leave the output unchanged. A tag holds
at most 95 bytes plus a NUL; `operation_bytes` and `operation_truncated` distinguish
a bounded prefix from a complete tag. Failure state is meaningful even when its
native domain/code is absent. Tags are diagnostics, never recovery or mutation
authority. This extension is separate from the frozen 0.4 Root/Tree headers.

## Unreleased 0.5 native synchronization semantics

Verified receipts, the two-way coordinator and named Keep Both resolution share
semantic policy schema V2. For qualified Windows DATA streams, it binds exact
native stream names, logical lengths and SHA-256 digests as well as preserved
attributes and security. Equal unnamed bytes cannot establish convergence when
named streams differ. Content budgets include all named DATA before capture
hashes those streams. Source membership is rechecked after the final digest;
inventory is revalidated before baseline commit.

A previous semantic policy remains a policy mismatch requiring review. Opening
a new API does not discard or silently reset its durable history. Named Keep
Both reviews bind both proposed exact names on both roots, protect both original
objects and keep their original conflict pending. Both reviewed versions must
be independently published and verified on both sides before the new version
paths enter the baseline. The current named-resolution provider admits regular
main-data files; its named-stream accounting and directory execution remain
separate qualification gates.

## Cached manual-name capability

`ckfet_name_feedback_get_v1` reports worker-assessed name-side eligibility and
selection errors without changing existing v1 layouts. Incoming KeepBoth/Rename
and Target KeepBoth have distinct required sides; retention and source metadata
qualification remain backend policy. Bind feedback to the plan generation, row
and completed assessment command. The fixed cached getter does no filesystem
I/O, allocation or rule evaluation. Read the
[name feedback contract](tree-name-feedback.md) before presenting its typed
reasons; eligibility never replaces native review or a receipt.
