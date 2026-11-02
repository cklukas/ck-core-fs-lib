# C API

The entry header is [`include/ck_file_engine.h`](../include/ck_file_engine.h).
`ck_fs_tree.h`, `ck_fs_actions.h`, and `ck_fs_session.h` expose native reviewed
execution, action jobs, and durable sessions. All headers are usable from C and C++ and contain no C++ types, exceptions, STL
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

Library 0.3 exposes ABI minor 3 with additive native execution and session
interfaces. Existing handles and snapshot layouts are unchanged.

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

`ck_fs_session.h` provides worker-only durable baseline sessions and verified
commit receipts. Open retains both root locks, including overlap protection;
commit is generation-checked and crash recovery preserves uncertain evidence.
These baseline primitives do not substitute for a composed two-way executor.

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
library does not validate or re-encode them, so non-UTF-8 native filenames are
not rejected. On Windows, `_utf8` inputs are decoded as UTF-8 and invalid
sequences are reported as Unsupported/UnrepresentableName. Windows callers that need exact
UTF-16 names can use the UTF-16 entry points. The native adapter performs the
final filesystem operation through its wide/native boundary; the C API's UTF-8
conversion is not a permission to use narrow Win32 I/O.
