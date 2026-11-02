# C API

The public header is [`include/ck_file_engine.h`](../include/ck_file_engine.h).
It is usable from C and C++ and contains no C++ types, exceptions, STL
containers, or frontend types.

## Ownership

`ckfe_engine_create`, `ckfe_directory_open_*`, `ckfe_entry_open_*`, and job
start functions return opaque handles owned by the caller. Destroy functions
release them. Destroying a job requests cancellation and joins its worker
before releasing native handles.

Initialize a `ckfe_error` with `ckfe_error_init`. Every API that accepts an
error output clears it on entry and overwrites it on failure; call
`ckfe_error_free` when done. Failed calls reset non-null output handles and
metadata to their empty values. The operation
string is allocated by the library and must never be freed with a language
runtime allocator.

## Jobs

Library 0.2 exposes ABI minor 2 with additive policy, events and recovery
interfaces. Existing handles and snapshot layouts are unchanged.

Start functions return quickly. `CKFE_API_OK` means a non-null job handle was
created; a rejected operation returns `CKFE_API_OPERATION_UNAVAILABLE` and a
structured `ckfe_error`, never a null job with an OK status. Polling is
nonblocking and returns a snapshot
with explicit `total_*_known` flags. Call `ckfe_job_cancel` for cooperative
cancellation and continue polling until a terminal state is observed. The
frontend owns presentation and conflict policy; the backend never calls back
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
Complete metadata scope retains the legacy strict capability gate. Ordinary
caller-visible scope is an explicit narrower request: mode 0777, atime/mtime,
and new-object effective UID/GID ownership (including correction of setgid-parent
group inheritance). Source ownership, birth/ctime, special bits, arbitrary
hidden xattrs and physical allocation identity are outside this scope. Known
visible attributes, ACLs, labels/capabilities, sparse/flagged/provider-managed
objects are currently refused when their preservation cannot be qualified;
ordinary scope does not claim replay of them. Unsupported Windows security
qualification remains a refusal. Exact timestamp/mode verification is required;
there is no precision or umask fallback.

`ckfe_job_get_preservation_report_v1` reports requested scope, achieved fields,
explicit exclusions, unknowns and provider qualification without requiring UI
code to parse diagnostic strings. Achieved fields are published only after
successful completion. Ordinary copying never implicitly authorizes source
deletion or retention of an old destination with excluded metadata.

Native journal setup and operation construction run on the job worker. Once
arguments are accepted, a start may return OK and later report a typed terminal
capability/access/setup failure. Polling and event draining must continue until
the terminal state. Snapshot events have a fixed 64-entry ring with explicit
coalescing counts; polling retains the final state independently of draining.

`ckfe_recovery_open_utf8` is a filesystem-worker read of a bounded private
journal. Immutable summary/page calls report durable states and review actions,
including untrusted tails/evidence. Inspection never authorizes automatic
replay, deletion or source retirement.

The next ABI slice will add opaque preview-plan and receipt handles. A plan
will carry the selected action profile, comparison mode, filters, link and
filesystem-boundary policy, and a stable decision token. Execution will accept
only a matching receipt and will revalidate held identities before mutation.
Unknown, unreadable, changed, or failed rows will remain typed review results;
they cannot become `identical` or authorize mirror deletion.

## Comparison and policy headers

`ck_fs_policy.h` contains fixed-width versioned preservation dispositions and
inventory assessments. It assesses explicitly supplied worker evidence; it does
not invent provider capabilities or authorize replay.

`ck_fs_plan.h` exposes opaque immutable comparison previews from bounded
caller-supplied facts. It provides summary/page/path access and whole-input
revalidation against plan-local tokens. It distinguishes incomplete inventory,
quick size/time equality and complete stable digests. Input facts cannot become
native operation authority through this interface. Native async inventory,
review receipts and execution of these plans are separate remaining gates.

## Native encoding

On POSIX, `_utf8` path/name inputs are byte-preserving component strings: the
library does not validate or re-encode them, so non-UTF-8 native filenames are
not rejected. On Windows, `_utf8` inputs are decoded as UTF-8 and invalid
sequences are reported as Unsupported/UnrepresentableName. Windows callers that need exact
UTF-16 names can use the UTF-16 entry points. The native adapter performs the
final filesystem operation through its wide/native boundary; the C API's UTF-8
conversion is not a permission to use narrow Win32 I/O.
