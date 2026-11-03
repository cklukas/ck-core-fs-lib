# Owned journal-root checkpoint

This is an unreleased 0.4 implementation checkpoint. It adds the owned
journal-root C API and guarded reviewed-tree integration. It does not enable
frontend Apply/write gates or qualify the separate 0.5 execution features.

The frozen Root11 implementation contains private-root ancestry and provider
checks, bounded private-file hard-link membership checks, worker-owned native
finalization, sticky native close errors, and the Windows mounted-volume
ancestry correction. Existing 0.3 Actions remain unchanged in this increment.

## Qualification recorded so far

| Check | Result |
| --- | --- |
| Linux production native suite and installed C consumer | PASS |
| CDE unchanged 70-file controller, original timeout and assertions | PASS, 27.05 seconds |
| Rebuilt ELF SDK: 18 CDE contracts and unchanged 70-file controller | PASS, 19.02 seconds; exact SDK mapping verified |
| Windows full native suite and installed C consumer | PASS |
| Windows NTFS/ReFS Root, scope and private hard-link checks | PASS |
| Windows long paths, exact UTF-16 C boundary and actual UNC refusal | PASS |
| macOS full normal suite | 25/30 PASS; five publication gates remain open |
| macOS full ASan/UBSan suite | 25/30 PASS; same five gates, no sanitizer finding |
| Final private hard-link fixture, macOS normal/ASan/UBSan/TSan | PASS, 109 checks per variant |
| Complete matching Root11 Linux ASan/UBSan qualification | 34/34 PASS on uconsole; byte-identical rpi4 binaries and matching runtime |
| Required committed Linux normal/ASan/UBSan/TSan CI | PASS at `e05a8fc` |
| Complete matching Root11 Windows ASan qualification | 30/30 PASS after complete corrected rebuild |
| Complete matching Root11 macOS TSan qualification | 25/30 PASS with qualified corrected runtime; same five publication gates |
| Ordinary metadata on actual ext4/XFS/Btrfs | PASS, 517 native checks per filesystem; complete scope remains unavailable |
| Actual Linux XFS/Btrfs whole SDK qualification | Failing: XFS 20/35, Btrfs 18/35; mount-ancestry gates remain |

The initial Windows ASan attempt omitted C++ exception-unwind support. It was
replaced by a complete matching rebuild with `/EHsc`, `/GR` and `/MD`. Both
normal and corrected ASan runs passed 30/30 suites, installed consumers,
long/exact UTF-16 paths, NTFS/ReFS and the UNC refusal checks. The invalid
initial attempt is retained as evidence and is not counted as a pass.

The complete Linux ASan build contains 141 instrumented translation units.
Its rpi4 runtime failed before `main` while reserving allocator memory. The
byte-identical binaries and matching runtime then passed 34/34 suites on
uconsole, including both namespace bootstrap modes. This establishes the
uconsole result; it does not establish a successful rpi4 sanitizer run.

The macOS failures are `regular_metadata`, `job_lifecycle`, `tree_c_copy`,
`tree_c_keepboth`, and `reviewed_tree_plan`. Strong descriptor-bound staging
publication remains unsupported. These mandatory positive tests are retained;
they are not suppressed, skipped, or relabeled as passes.

The stock macOS TSan runtimes report a race in a standalone detached-thread
test that writes only native thread-local `errno`. A correction based on LLVM
23.1.4, commit `7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`, records the exact
four-byte native TLS lifetime. Positive detached/joined and GCD tests passed;
deliberate foreign-thread races remained detectable. All 45 enabled upstream
unit tests and four focused shadow tests passed; eight pre-existing disabled
unit tests are not counted. No sanitizer exclusions or product serialization
were introduced.

The corrected arm64 runtime SHA-256 is
`124e6acd2266a0526f9184c852ca6f3270997378bdbcedc22c72765b4d155890`.
A fresh matching LLVM 23.1.4 build of all 122 Root11 translation units passed
the race gate, with only the same five mandatory publication tests failing.
This result cannot establish a stock-runtime pass.

## Source and artifact identity

The qualification source manifest contains 312 files and has SHA-256
`01bfdebac99aba94d40ef1853815b28aa07e3edd669677fbff1d63c5c01b969d`.
The public Root and Tree headers retain the reviewed 0.4 contract. Native
implementation bytes are frozen across these runs; later documentation
corrections preserve the existing terminal-I/O CI results.

The production Linux SDK uses uniform GCC 14 `-O1 -g0`, assertions enabled,
and a distinct install prefix. The unchanged consumer uses GCC 12. Earlier
unoptimized timeout failures remain recorded and are not claimed to pass.

No final release tag or frontend dependency pin is established by this
checkpoint. Platform qualification and the existing publication/preservation
gates remain mandatory.

## Isolated Linux mount fixture

The initial GitHub Linux runs passed 33 of 34 native tests. The remaining
fixture could not write its UID mapping under the hosted runner's namespace
policy. This is an unqualified fixture result, not a product pass or a skipped
test.

The fixture now supports an explicitly selected `privileged-id-map` bootstrap.
Its privileged parent maps only its own waiting child to the ordinary caller's
host UID/GID. The child clears supplementary groups, drops the host identity,
creates a private mount namespace, sets no-new-privileges and executes the
native test. Before native operations, the test verifies both namespace
identities, all real/effective IDs and the exact one-row UID/GID maps. The
parent uses PID handles to terminate its own payload on caller exit or timeout.
No host mounts or host security settings change. The default bootstrap remains
unprivileged; neither mode turns an unavailable fixture into success.

Both complete native mount matrices passed against the frozen Root11 GCC 14
implementation on Linux. Invalid modes, host-root execution and zero-host-UID
mapping were rejected. Caller-exit cancellation also terminated the isolated
payload. GitHub CI selects the explicit bootstrap and checks its prerequisites
before compiling. A subsequent ASan run exposed a test reference into a
temporary progress snapshot. The fixture now owns that snapshot before
accessing its failure; the complete instrumented rerun passed.

The committed checkpoint passed all required jobs in
[CI run 41614017099](https://github.com/cklukas/ck-core-fs-lib/actions/runs/41614017099).
The matching compiler's shared Linux TSan runtime is selected explicitly;
allocator failure, actual runtime image and deliberate heap-race controls also
pass. Documentation publication passed in
[Pages run 41615124078](https://github.com/cklukas/ck-core-fs-lib/actions/runs/41615124078).

## ELF packaging gate

An independent interposition test confirmed that an executable could replace
an internal C session opener and pass a foreign opaque handle to the verified
wrapper. The baseline changed 12 bytes in a foreign buffer. The candidate
SDK binds internal calls locally and hides private C++ symbols. Its actual
GCC 14 build passed 35/35 suites and the installed C consumer; the same probe
reported zero intercepted calls and zero foreign writes. The strict export
audit initially found five weak standard-library helpers containing private
type arguments. Localizing private archive symbols removes those exports;
the final SDK retains all 110 public C functions and passes the same probe,
35/35 suites and the installed consumer. The final SDK SHA-256 is
`973bddbe78326975853c1663357007916c1779f93f3beedaa999b27238e524f6`.
Its relink took 0.76 seconds: all 142 object hashes and timestamps, all 719
compile-closure inputs, and every compile command remained unchanged. This
establishes a link-only rebuild rather than inferring freshness from duration.
A separate export-surface test checks all public declarations and rejects
private type names even inside standard-library template arguments.

The CDE peer requalified all 18 consumer contracts and the unchanged 70-file
controller against that exact SDK. The controller completed in 19.02 seconds
with its original 30-second loops and 45-second driver deadline. Runtime maps
confirmed the single intended SDK; source and SDK hashes remained unchanged.
These headless tests do not load Motif, whose frozen library bytes were checked
separately.

The initial instrumented ELF probe was a C-only host that loaded the C++ SDK
with `dlopen`. ASan initialized before the C++ exception runtime was loaded and
could not resolve its real exception interceptor. The other 35 ASan tests and
the export audit passed. The host now has a separately instrumented C++
exception control and a startup dependency on that runtime, while the probe
itself remains compiled as C. An independent, fully matching ASan/UBSan C/C++
plugin test passes and verifies that the C++ runtime loads before `main`.
The complete committed SDK CI rerun remains required.

No final dependency pin or release is established by this packaging increment.

## Actual XFS and Btrfs fixtures

Disposable one-GiB images were formatted with xfsprogs 6.13.0 and btrfs-progs
6.14 on Linux 7.1.4. The privileged fixture process mounted each image only in
its private mount namespace. Every product test ran as host UID/GID 1000,
with no supplementary groups, no capabilities and no-new-privileges. Binary
hashes remained unchanged. Both filesystems unmounted and their exact owned
loop devices detached successfully; unrelated devices were untouched.

XFS passed 18/35 tests and Btrfs passed 16/35. Journal-root preparation refuses
mount crossings because namespace parent traversal alone cannot establish
physical ancestor coverage. Btrfs session ancestry has an additional ambiguity
refusal. These are failing positive qualifications; their guards remain
mandatory while native mount-root evidence is implemented and tested.

The subsequent narrow Ordinary metadata increment passed 517 native checks
each on ext4, XFS and Btrfs, as the same ordinary UID with zero capabilities.
It retains actual held-descriptor identity, access, owner, ACL, xattr and
storage-policy checks. Only ext4 extent/directory-index representation and
XFS's attribute-fork representation are accepted. Compression, NOCOW, DAX,
inheritance, project/extent/COW policies and unknown bits remain refused.
Complete/birthtime preservation is not newly qualified.

With that increment, ext4 passed all 35 SDK suites; XFS passed 20/35 and Btrfs
18/35. The independent default policy audit adds 282 checks. Its pass is
separate from the native capability-bearing fixture results and cannot stand
in for whole-filesystem qualification.
