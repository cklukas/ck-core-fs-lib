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
| Actual Linux XFS/Btrfs runtime qualification | Pending |

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
audit still found five weak standard-library helpers containing private type
arguments. That remaining packaging correction is under qualification. No
final dependency pin or release is authorized by the candidate result.
