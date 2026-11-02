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
error output overwrites it; call `ckfe_error_free` when done. The operation
string is allocated by the library and must never be freed with a language
runtime allocator.

## Jobs

Start functions return quickly. Polling is nonblocking and returns a snapshot
with explicit `total_*_known` flags. Call `ckfe_job_cancel` for cooperative
cancellation and continue polling until a terminal state is observed. The
frontend owns presentation and conflict policy; the backend never calls back
into the UI.

## Encoding

UTF-8 paths are accepted for portable callers. Windows callers that need exact
UTF-16 names can use the UTF-16 entry points. The native adapter performs the
final filesystem operation through its wide/native boundary; the C API's UTF-8
conversion is not a permission to use narrow Win32 I/O.
