# C++ API

The installed C++ targets separate filesystem mechanisms from browser policy:

- `ck::ck_core_fs_engine` provides identity-aware cursors, filesystem operations,
  and reusable directory-index record encoding and storage primitives.
- `ck::ck_files_platform` links the engine and adds native metadata, index-file,
  journal-file, and home-directory adapters.
- `ck::ck_core_fs_native` links the platform boundary and composes reviewed
  tree execution, retained-target publication, and native action workers.
- `ck::ck_core_fs_browser` is an optional higher-level library that links the
  engine publicly. It provides pane models, commands, acquisition, refresh,
  paging, ordering and filtering, plus indexed panes and their listing, sorting,
  lookup and mark jobs. These directory-index jobs depend on pane requests,
  ordering, filtering or selection, so they belong to the browser layer.

In a source build, link the same target names without the `ck::` prefix. The
compatibility alias `ck_file_engine` names `ck_core_fs_engine`; `ck_files_core`
names `ck_core_fs_browser` so ckUtilities retains its browser functionality.
These aliases are for `add_subdirectory` consumers and are not installed.

`CK_CORE_FS_BUILD_BROWSER` defaults to `ON`. Set it to `OFF` for a standalone
engine/C ABI build; the browser target, its compatibility alias, archive and
export are then omitted. The C ABI target `ck_file_engine_c` (installed as
`ck::ck_file_engine_c`) links native composition, platform and engine code. It never compiles
or links browser policy, even when the browser library is enabled. Consumers
using native platform factories alongside browser models should link both
`ck::ck_core_fs_browser` and `ck::ck_files_platform`.

Native headers live under `src/files` in the source checkout and are installed
under `include/ck-core-fs`. They expose the identity-aware cursor and operation
types used by the existing ckUtilities file frontend. Headers are installed
with either configuration; using browser implementations requires enabling and
linking the browser target. The C ABI and browser share the same engine, so
there is one filesystem implementation and one set of platform safety behavior.

Prefer the C ABI for a language or process boundary. Use the C++ targets only
when the consumer can follow the library's C++ toolchain and ABI policy.
