# Building and testing

Native test fixtures default to `build/tasks`. Set
`CK_CORE_FS_NATIVE_TEST_ROOT` to an explicit isolated directory when the build
volume has different semantics from the provider being qualified. A macOS
`noowners` mount cannot establish private journal or ownership-preservation
guarantees. Keep build intermediates on an approved temporary volume and use
an ownership-enforcing approved temporary volume for positive native fixtures;
test `noowners` refusal separately. Do not change global mount settings to make
a test pass.

The library is a standalone CMake project. For POSIX builds, first select a
fresh absolute `CKFS_WORK` directory and a private, ownership-enforcing
`CKFS_FIXTURES` directory. On macOS verify the temporary volume is mounted and
create work beneath `/Volumes/S8T/tmp` (preferred) or `/Volumes/PRO-BLADE/tmp`;
never use system temporary storage. Native ownership fixtures need an approved
ownership-enforcing volume, independently of where the build lives. On remote
Linux hosts choose a sensible unique local workspace. Keep existing active
builds and peer work intact.

```sh
: "${CKFS_WORK:?select a fresh absolute approved workspace}"
: "${CKFS_FIXTURES:?select an isolated native fixture directory}"
export TMPDIR="$CKFS_WORK/tmp" TMP="$CKFS_WORK/tmp" TEMP="$CKFS_WORK/tmp"
mkdir -p "$TMPDIR" "$CKFS_FIXTURES"
cmake -S . -B "$CKFS_WORK/build" -DBUILD_TESTING=ON \
  "-DCK_CORE_FS_NATIVE_TEST_ROOT=$CKFS_FIXTURES"
cmake --build "$CKFS_WORK/build" --parallel 1
ctest --test-dir "$CKFS_WORK/build" --parallel 1 --output-on-failure --no-tests=error
cmake --install "$CKFS_WORK/build" --prefix "$CKFS_WORK/install"
```

For full Windows qualification use `tools/qualification.cmake` with fresh
absolute `QUALIFICATION_OUTPUT`, explicit `QUALIFICATION_NATIVE_TEST_ROOT`, and
`QUALIFICATION_WINDOWS_TEST_FS=NTFS` or `ReFS`. On the workstation all paths and
`TEMP`, `TMP` and `TMPDIR` must be on `V:`; set `CK_FS_REQUIRE_V_DEV_DRIVE=1`.
The driver propagates the selected actual provider to archive and metadata
fixtures, admits output ancestry before creating it, and checks for known unsafe
legacy runtime-hook fixtures **before configure or native execution**. That
preflight currently refuses 48 findings in 14 retained fixture sources. Windows
full qualification remains blocked until their compiled-hook migration is
complete; do not bypass the gate or run the generic full Windows test set.
The independently qualified, scoped journal-close target is described in
[the native contracts](native-contracts.md#windows-journal-temporary-close-errors).

The C ABI smoke test is compiled as a C translation unit and verifies that the
installed-facing header remains C-compatible. Platform qualification targets the
same project on Linux, macOS, and Windows; a platform admission or runtime
failure remains an open gate. Add path, identity, cancellation,
and reparse/security regression tests before changing a native boundary.

## Independent installed-C capability gates

`tests/contract-consumer` is a separate C-only project that consumes the
installed package. It keeps fourteen behavioral contracts, including preservation
success gates that currently fail on unsupported scopes/providers. It is not
part of the default passing core CTest set, and its failures must not be
converted to expected passes. See its README for an explicit build/fixture
directory invocation. Use approved temporary volumes on macOS and the mandatory
V: development drive on the Windows workstation.

The Complete-metadata success gates remain unresolved. Ordinary local-file
success is independently established on Linux ARM64; the current macOS fixture
is refused for opaque `com.apple.provenance` metadata. Cancellation tests using
small files qualify only their observed cancellation/completion outcomes, not
latency during blocked native I/O.

## Native Windows Tree and security qualification

Windows builds register the native Tree, independent target-reader, wide fixture
boundary and consumed-source-close tests only on Windows. The no-op portability
entry points in their translation units do not count as platform qualification.
Select the actual provider with
`-DCK_CORE_FS_METADATA_TARGET_NATIVE_FS=NTFS` or `ReFS` and set an explicit
`CK_CORE_FS_NATIVE_TEST_ROOT` on that provider. Workstation roots must remain
beneath `V:\tmp`, including volume-mounted ReFS fixtures.

The ordinary target-reader test runs without enabling privileged security
replay. Explicitly configure `-DCK_CORE_FS_TEST_PRIVILEGED_METADATA=ON` to register
the Complete target-reader and Tree security cases. Those tests require genuine
SeSecurityPrivilege; missing access is a failed qualification, never a silent
success or automatic elevation. No system security configuration is changed.

The new normal Tree test has measured unoptimized baselines of approximately
458 seconds on NTFS and 697 seconds on ReFS. Its 1,200-second deadline and the
600-second controls deadline are distinct from existing suite deadlines. A
normal result does not qualify a sanitizer build. All product and consumer
translation units must use matching headers, runtime, instrumentation and C++
layouts; the unreleased Tree request layouts changed in this checkpoint.

## Static library boundaries

Portable policy, digest, cleanup and budget primitives belong to Core. Native
capture/replay/preservation/copy workers and session-root acquisition belong to
Platform with their native provider implementations. Tree/action/session
composition belongs to Native. Link the exported target matching the API you
use; Core alone intentionally does not supply native workers.

`tests/installed_layers` builds independent consumers of Core, Platform, Native
and the C facade against one freshly installed prefix. Each consumer links one
exported target. The archive-dependency test rejects reverse implementation
edges. Repeating archives, grouping them or forcing whole-archive linkage is not
a substitute for the dependency boundary.

For native Windows consumed-close and pending-writer regressions, configure
`-DCK_CORE_FS_TEST_NATIVE_CLOSE_HOOKS=ON` with `BUILD_TESTING=ON` and an explicit
`CK_CORE_FS_NATIVE_TEST_ROOT` on the selected qualified filesystem. The option
adds 49 native modes and compiled failure-only seams; it is off by default.
Use a coherent dedicated SDK build for this configuration, with the same
instrumentation and headers for its consumers.
