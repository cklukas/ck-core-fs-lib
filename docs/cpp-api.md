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

`metadata_ownership_digest.hpp` provides a pure comparison key for known
ownership observations. POSIX keys include uid/gid; Windows keys include the
exact requested owner/group SIDs, independent of self-relative descriptor
packing or Access/Full query format. Unknown or unrequested ownership is
refused, and inconsistent descriptor observations remain Changed. This key
supports equality checks when a CurrentCaller preservation policy omits actual
owners from its cross-object metadata digest. It authenticates no native issuer
and grants no replay or mutation authority; native producers must qualify their
snapshots separately.

## Held journal inspection

`operation_journal_file.hpp` provides worker-only observation of existing
private journals through the platform target:

- `open_native_operation_journal_directory` acquires and qualifies the initial
  native directory once. Windows requests list/attribute access and
  `READ_CONTROL`; ordinary directory browsing keeps its existing access rights.
- `open_held_operation_journal_file` opens an existing private, regular,
  single-link file relative to that retained directory. Keep its `NativeName`
  unchanged; display text and the directory's former pathname are not reopening
  authority. The file's `write_at` and `flush` return Denied without issuing I/O.
- The file's `finish_io` and `finish_operation_journal_directory` explicitly
  consume their native owners and cache completion, including native failures.
  Finish every acquired owner on returned-error and exception paths. Repeating
  completion must not close a reused descriptor. After directory completion,
  only repeated completion and destruction are permitted.

The directory is a generic `DirectoryCursor`, not a restricted authority type.
Its caller must follow the observation-only scan protocol and must not invoke
mutators or access upgrades. These factories issue no `PreparedJournalRoot`,
review receipt, publication capability, or retention guarantee. They never
prepare a public directory to make it private. Windows sharing excludes live
data writers; POSIX identity/version bookends remain observations rather than
a writer-exclusion lease or immutable snapshot.

The native UNIX regression covers held-root replacement, ordinary and long
paths, write/flush refusal, private ownership, symlink/hardlink refusal, and
consumed and repeated completion. Matching frontend qualification also covers
Windows NTFS/ReFS long roots and raw UTF-16 names. Those focused results do
not close full-application, UNC/provider, or Windows close-fault qualification.
