# ck-core-fs-lib

Headless, cross-platform filesystem operations for ckUtilities, CDE, and other
frontends. The project has no ckVision, terminal, Motif, or UI dependency.

The public boundary is the exception-free opaque-handle C API in
`include/ck_file_engine.h`. C++ consumers use the same native implementation
through the exported `ck::ck_core_fs_engine`, `ck_files_platform`, and
`ck_core_fs_native` targets while
the C ABI provides stable ownership, polling, cancellation, structured
metadata, and terminal job states.

The C ABI includes held-handle inspection, journaled regular-file jobs,
native reviewed-tree workers, action jobs, and durable session contracts.
The implemented scopes and their provider limits are described in
[`docs/native-contracts.md`](docs/native-contracts.md). Qualification is tracked
per revision; enum values and safe refusals do not establish feature readiness.
The operation model is
documented in [`docs/operation-planning.md`](docs/operation-planning.md):
versioned preservation policy, bounded comparison/planning, reviewed conflict
receipts, recursive update/sync/mirror execution, rename/delete/Trash adapters,
events, and recovery. The implementation
must not collapse them into frontend policy or shell out to another tool.

Windows code must retain wide/native handle boundaries and extended-length
path semantics. POSIX code keeps byte-native names. No final filesystem I/O is
performed through narrow Win32 APIs or `std::filesystem`.

## Local integration

ckUtilities consumes this project with `CK_CORE_FS_LIB_SOURCE_DIR`, defaulting
to the sibling checkout `../ck-core-fs-lib`. A later GitHub checkout can be
selected with the same CMake cache variable without changing the ckVision
frontend.
