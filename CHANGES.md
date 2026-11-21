# Changes

## Unreleased 0.5 development checkpoint

- Add Linux native directory creation (`mkdirat(..., 0700)` + held `O_RDONLY |
  O_DIRECTORY | O_NOFOLLOW` writer/cursor/verifier opened via `openat(writer_fd,
  ".")` + parent `fsync`) on qualified `ext4`, `XFS`, and `Btrfs` mounts, while
  keeping Darwin directory creation explicitly `Unsupported`.
- Add additive held-parent namespace policy opt-in for Linux reviewed tree
  mutation (`CKFET_OPTIONS_V2_VERSION`, `CKFET_NAMESPACE_HELD_PARENT_RENAME`,
  `ckfet_options_v2`, `ckfet_options_init_v2`, `ckfet_start_v2`,
  `ckfet_start_with_journal_root_v2`), qualifying safe `.ck-retire-<pid>-<seq>`
  `renameat2(..., RENAME_NOREPLACE)` + post-rename `statx`/`fstatat` identity
  verification (restoring the original entry without unlinking on concurrent
  mismatch) for reviewed `Mirror` file/empty-directory deletion and retained
  `Replace` execution, while preserving strict handle-lock `Unsupported`
  refusals on default v1 entry points.
- Add additive recursive two-way tree synchronization (`CKFSS_TWO_WAY_TREE_VERSION`,
  `ckfss_two_way_tree_options_v1`, `ckfss_two_way_tree_options_init_v1`,
  `ckfss_two_way_open_tree_v1`), extending `NativeSyncCoordinator` with bounded
  recursive directory tree inventory (`NativeSyncDirectoryProof`), nested
  absence proofs, pre-order directory creation, file copy/retained replacement,
  post-order empty-directory removal, root-container retained artifacts, and
  canonical `hierarchy_magic` (`NativeSyncLedger::create_hierarchy`) ledger
  parent-closure encoding while preserving flat-only v1 behavior on
  `ckfss_two_way_open` and `ckfss_two_way_open_with_journal_root`.

- Release the transient `2 * max_native_bytes` native attribute/security read
  scratch reservation from `MetadataCaptureBudget` once a `MetadataCaptureJob`
  seals its `NativeMetadataProof` (or terminates), retaining only the sealed
  proof's actual metadata footprint so multi-file `ckfet_start_v1` tree
  executions with retained target-verification seeds do not exhaust the 64 MiB
  metadata budget after 32 files.

- Add `include/ck_fs_search.h` (`ckfes_*`), a worker-owned, cancellable
  recursive filename (substring/glob) and regular-file content search C ABI
  built on handle-relative `DirectoryCursor` and `OpenedEntry` primitives
  without following descendant symlinks or reparse points. Supports size and
  modified-timestamp bounds, binary-file content skipping, incremental page
  streaming while `CKFES_RUNNING`, exact relative path byte/UTF-16 copy, and
  explicit `ckfes_worker_drained_v1` lifetime coordination.

- Replace the remaining unsafe Windows fixture interception with compiled,
  read-only native observations; retain all fourteen legacy entrypoints and
  real read/completion/drain error channels. Guard private fault storage with
  BUILD_TESTING and match installed test-client profiles explicitly. The
  combined source passes 67 normal macOS SDK tests and five installed consumers;
  full Windows, sanitizer and production-OFF qualification remains open.

- Replace the Copy, target-read Seed, Sync and held-journal-reader Windows
  close fault imports with compiled observers after genuine native operations.
  Qualify 80 focused cases on NTFS/ReFS in each normal and matching ASan mode,
  including real close failures, first-error retention and allocation denial.
  Give Seed invocations exclusively created native workspaces and retain
  per-invocation executable/ASan-module evidence. Remaining legacy fixtures
  and the complete Windows qualification gate stay open.
- Add worker-owned stable C Actions-with-Root, Trash/restore, and verified
  retry/prefix-copy jobs with one-use review and explicit native drain.
- Add V3 semantic metadata evidence, bounded native source capture, independent
  stream verification, and proof-backed regular/directory metadata workers.
- Add durable native two-way coordination and reviewed version-retention
  candidates, retaining lock, ledger, stale-review and pre-CAS close checks.
- Keep whole Tree receipt integration, hierarchical convergence, provider
  limitations and final matching sanitizer/consumer qualification as open gates.
- This checkpoint is not a release or a frontend Apply/pin approval.

## 2026-11-03

- Add the 0.4 owned journal-root factory and guarded Tree integration.
- Isolate native private state before mutating inventory and revalidate it
  through review/execution; refuse translated providers and mount aliases.
- Keep native consumer/root finalization on workers and preserve delayed errors.
- Version the shared runtime identity as 0.4, including the Windows DLL.
- Keep new Actions-with-Root/session/retry interfaces in the 0.5 increment.
- Preserve provider refusals and unresolved positive publication gates.

## 2026-11-02

- Interlink the ck-core-fs-lib, CK Core CDE, Apps and Motif documentation sites
  through their site selectors and front-page project panels.
- Build GitHub Pages with the selector-capable ckdocs v0.10.1 source pin used
  by the related CK Core documentation sites.
