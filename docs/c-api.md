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

The next ABI slice will add opaque preview-plan and receipt handles. A plan
will carry the selected action profile, comparison mode, filters, link and
filesystem-boundary policy, and a stable decision token. Execution will accept
only a matching receipt and will revalidate held identities before mutation.
Unknown, unreadable, changed, or failed rows will remain typed review results;
they cannot become `identical` or authorize mirror deletion.

## Encoding

On POSIX, `_utf8` path/name inputs are byte-preserving component strings: the
library does not validate or re-encode them, so non-UTF-8 native filenames are
not rejected. On Windows, `_utf8` inputs are decoded as UTF-8 and invalid
sequences are reported as Unsupported/UnrepresentableName. Windows callers that need exact
UTF-16 names can use the UTF-16 entry points. The native adapter performs the
final filesystem operation through its wide/native boundary; the C API's UTF-8
conversion is not a permission to use narrow Win32 I/O.
