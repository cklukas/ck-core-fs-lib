# ck-core-fs-lib

Headless, cross-platform filesystem operations for ckUtilities, CDE, and other
frontends. The project has no ckVision, terminal, Motif, or UI dependency.

The public boundary is the exception-free opaque-handle C API in
`include/ck_file_engine.h`. C++ consumers use the same native implementation
through the exported `ck::ck_core_fs_engine`/`ck_files_platform` targets while
the C ABI provides stable ownership, polling, cancellation, structured
metadata, and terminal job states.

The first consumable revision exposes held-handle directory/entry inspection
and journaled regular-file copy and move jobs. Recursive delete, rename,
capability adapters, conflict decisions, recovery inspection, and event-drain
surfaces remain explicitly tracked extensions; the implementation already
contains the lower-level identity/recovery primitives that those APIs will
wrap.

Windows code must retain wide/native handle boundaries and extended-length
path semantics. POSIX code keeps byte-native names. No final filesystem I/O is
performed through narrow Win32 APIs or `std::filesystem`.

## Local integration

ckUtilities consumes this project with `CK_CORE_FS_LIB_SOURCE_DIR`, defaulting
to the sibling checkout `../ck-core-fs-lib`. A later GitHub checkout can be
selected with the same CMake cache variable without changing the ckVision
frontend.
