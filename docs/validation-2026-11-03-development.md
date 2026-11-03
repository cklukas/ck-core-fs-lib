# Execution development qualification

These results describe frozen development snapshots. They do not establish a
0.5 release, a frontend dependency pin, or permission to enable Apply.

## Windows combined snapshot

The 347-file snapshot has input manifest SHA-256
`452f3f6d61cc15a971efa4055f3e1c751b3244e6b4f2e4c802d0268e4c6c76a3`.
Two test-fixture corrections normalize extended Windows paths without changing
product implementation or relaxing assertions. The qualified manifest is
`22831dae16e12b24e26bb686d92227709b6b3d899b5dfa3c8fdf9e1f39c6b756`.

| Check | Result |
| --- | --- |
| Full native CTest suite, normal | 41/41 PASS |
| Full native CTest suite, matching MSVC ASan | 41/41 PASS |
| Matching compilation | 154 translation units; 146 C++ with `/EHsc /GR /MD`, eight C11 |
| Installed C11 consumer and DLL contracts | PASS, both variants |
| NTFS/ReFS private Root, scope, hard-link membership, security and ADS | PASS, both variants |
| Long paths, raw UTF-16 names and explicit UNC refusal | PASS, both variants |
| Two-way coordinator: mixed directions, restart, locks, stale review, cancellation and pre-CAS recovery | 302 checks per filesystem and variant PASS |
| Actual close and allocation-failure boundaries | 18 ownerless and 20 Root-bound cases per variant PASS |

Normal DLL SHA-256:
`3f4c89930691d6516dfb99304e133fe30a445a79ad5b69442bc018639ab319d1`.
ASan DLL SHA-256:
`1c209badd1c0fab74332e67f86cb021ead956866fdb96a5cc4e97e72dae6bf97`.
The respective install prefixes are beneath
`V:\tmp\ckfs-v05-combined-win-20261103-ag\normal\install` and
`V:\tmp\ckfs-v05-combined-win-20261103-ag\asan\install`.

This snapshot excludes the subsequent progressive metadata scanner, native
directory replay executor, and Windows named KeepBoth implementation. Its
Windows resolution path still returns typed Unsupported. These passes must not
be attributed to those later changes. MSVC ASan is not a Windows TSan or UBSan
qualification. Successful directory flush calls establish API acceptance;
this run did not simulate power loss or qualify a custom filesystem driver.

## Cooperative metadata phases

Commit `3ef556b` adds an exclusive cooperative phase adapter to the internal
metadata job. A Pending result retains the current phase; one advance calls
only one adapter. Native errors retain precedence over cancellation, and
terminal results remain cached. Existing single-call false results still fail.

All 97 focused checks passed in normal and matching ASan/UBSan builds, with
warnings treated as errors. This qualifies the phase framework. Incremental
native capture, stream replay, final timestamp handling and independent target
verification need their own integrated native results.

The subsequent explicit clean-cancellation result is accepted only with a
requested stop. An unrequested cancellation fails; unavailable native errors
still retain precedence. The expanded 103-check suite passed normal and
matching ASan/UBSan builds with warnings treated as errors.

## Subsequent focused native components

These later tests use separate frozen dependency closures. They do not inherit
the combined Windows snapshot's sanitizer results.

| Component | Native normal evidence | Boundary |
| --- | --- | --- |
| Fresh regular-file execution source | Linux ARM64/ext4, ordinary UID: PASS in 2.64s; Windows x64/NTFS: PASS in 8.42s | Reviewed V3 metadata and main SHA, Original/CurrentCaller, two rechecks retaining the original open proof, bounded reads, cancellation and actual consumed-close faults; no target or Tree composition claim |
| Private target stream bridge | NTFS and ReFS: 12/12 each | Genuine private targets only, independent readers opened before final security, per-handle timestamp suppression, empty streams, flush/close/allocation faults and Root latching; normal only |
| Regular metadata worker | Linux ext4, ordinary UID: four native cases PASS | Original/CurrentCaller replay, cancellation, consumed close failure, two fresh source observations and read-free publication verification; component linkage only |
| Directory metadata workers | Ownership-enforced macOS APFS: 1,467 checks PASS | Existing-directory proof-backed worker, bounded read/write steps and retained source proof; new POSIX directory publication remains Unsupported; no whole Tree claim |
| Explicit metadata-loss source observation | macOS APFS, Linux ext4, Windows NTFS/ReFS: focused producer and Scanner suites PASS | Two-pass main-content SHA only; unavailable metadata remains Unknown; no implicit weaker metadata policy or replay authority |
| Read-only hard-linked source capture | Linux: 102 checks; NTFS and ReFS: 299 each | Writable target single-link checks remain; no promotion of unavailable Complete security coverage |

The regular source closure's three-file manifest is
`b3e43c2e68b514189ba5ad5f268f25b1ed91f4c71c12c360cf5f324431759310`
(header),
`69f459207aee006f1b19111ae32f9e9807e6dba57d5e272207c9220039fa646f`
(implementation), and
`205dd7d5cbda6ccbfed59823e3370a7f970fae2979e6af229e4ab772c7621d99`
(fixture). The explicit-loss producer/Scanner frozen manifest is
`0da17b28cc220a63b24a27cbfa3e7186fe6a5b80e27e336572b65f54dbdcfcce`.

A subsequent coherent 411-file macOS component snapshot has manifest
`b48cac6c7c5b0cdceeddde41e2a193f0486a35d2786e6224df4547da71b00466`.
Its clean 120-step build completed in 306.20s with one compiler, `-O1 -g0`,
and no compiler cache. All six selected tests passed in 2.63s: main-content
producer, regular execution source, directory workers, metadata capture,
progressive metadata Scanner, and explicit-loss Scanner. The snapshot uses
directory worker v1; the subsequently integrated v3 values cache has separate
native evidence (3,238 macOS checks and 11,173 each on NTFS/ReFS). Neither
result establishes whole Tree composition or matching sanitizer qualification.

The next coherent Linux ARM64/ext4 416-file snapshot has manifest
`ae62828d65d71ed03392382597a57383152b50781332bd1161e3d9f87a7cc9f0`.
Its fresh GCC 14 Debug build (`-O0 -g0`, one CPU) passed in 509.78s; all nine
selected native tests passed in 23.09s. A recorded derivative replaced only
the membership diagnostic implementation and added two regression fixtures;
all original header bytes and remaining compile commands stayed unchanged.
The expanded eleven-test run passed in 62.46s, including actual consumed
source/HeldChild/directory close faults before baseline CAS and the six
progressive metadata review regressions. This is normal component qualification,
not a whole Tree, O2, sanitizer or physical power-loss result.

The membership fix propagates allocation failure after native owners drain,
rather than constructing another diagnostic with an empty string: MSVC debug
iterator storage can allocate even for that fallback. The unchanged Windows
native test passed 117 ordinary-path and 118 long-path checks after this fix.

## ELF Debug export boundary

The Debug installed consumer passed, but a stricter export audit then exposed
30 default-visible C++ standard-library definitions from facade object files.
Archive hiding alone does not cover those direct objects. An ELF export map
now limits the runtime to the seven public C API families; the audit compares
the entire defined export set with public header declarations, including
standard-library names rather than only `ck::files` names.

The recorded Debug baseline fails the stronger audit. The mapped derivative
exports exactly the same 170 C functions and zero C++ symbols. The build-tree
and installed audits, actual interposition probe, native C resolution roundtrip,
and installed ISO C11 consumer all pass. Only the shared runtime was relinked;
the native static archive bytes and source/header cohort were unchanged.

## Matching macOS sanitizers

A fresh ownership-enforced APFS run passed all seven selected tests under
ASan and UBSan in 4.30s, with no sanitizer diagnostics. All 130 product
translation units and six test objects carried matching instrumentation.
The derivative manifest is
`8ae4f343a00329ee8f1a554766b9bcfc48740e5579f495cedc8e114e1cdec446`.
The tests cover main-content production, regular execution source, v3
directory workers, metadata capture, progressive review cleanup, and both
Scanner paths. The Linux-only ancestry-method guard matches the tested
source exactly. This snapshot predates the subsequent base copy-source drain
and deferred protocol-diagnostic changes; those need their own qualification.
Positive macOS publication remains an open gate.

## Linux native mount identity

The frozen Root 0.4 candidate, based on `e89504e`, passed all 40 native tests
and its installed consumer separately on ext4, XFS, and top-level Btrfs.
Every run used UID/GID 1000, no supplementary groups, and cleared capability
sets on Linux ARM64 7.1.4 with GCC 14. Its source manifest is
`0d5290bf66c2f913c969c3b282a027b8fc50d0fb9c5c11a527cc52fbc38cc598`;
the installed library hash is
`eb62a2849796b48092513e2307991c44aca7b34e5f38a9fb8d7d6e684faff3bd`.
This is normal Root qualification, separate from the 0.5 integration and
export-map derivatives above.

Mount witnesses retain statmount superblock device fields separately from
statx/fstat VFS identity, with native mount IDs, filesystem IDs, attributes,
mount-root endpoints and before/after checks. The Btrfs run observed SB `0:60`
and VFS `0:61`; no filesystem-specific bypass is used. Btrfs qualification
covers top-level subvolid 5. Mounted non-root subvolumes remain refused.

A separate native-query eligibility probe also passed on rpi4 Linux 6.18.34
as UID 1000 with zero effective/permitted/inheritable/ambient capabilities.
It is not a full controlled-privilege or SDK qualification: its bounding set
remained nonzero and NoNewPrivs was zero. No kernel compatibility fallback
was needed for that query.

The lifecycle fixture's old duplicated directory stream missed populated
Btrfs entries during teardown. Its qualified derivative opens a fresh iterator
through held `fd/"."`, checks inode/device identity and retains every assertion.
All 108 production artifact hashes and production compiler commands stayed
unchanged through that fixture rebuild. Failed runs and their diagnostic
evidence remain recorded; no sleep or weakened assertion was used.

The later coherent Windows and macOS integration runs still fail Tree receipt
validation after publication. Passing source and metadata components therefore
do not establish receipt-bound execution completion.

## Relocatable pkg-config metadata

The generated pkg-config file now derives relative installation directories
from its own installed location. Explicit absolute GNUInstallDirs destinations
retain their configured meaning. This fixes the embedded `/usr/local` prefix
that required the CDE requalification to use a consumer-side override.

Two actual ISO C11 consumers passed after moving independently staged SDKs
into paths containing spaces: the default `lib`/`include` layout and
`lib/aarch64-linux-gnu` with `headers/custom`. Each was compiled with GCC 14,
`-std=c11 -Wall -Wextra -Wpedantic -Werror`, using only pkg-config's flags;
loader inspection confirmed the relocated runtime. Neither configured original
prefix existed, and the copied runtime and protected source SDK retained their
SHA-256 identities. These packaging checks reuse the previously qualified Linux
runtime; they do not qualify subsequent native-execution changes.

## Consumed-close checks before baseline commit

The Linux pre-CAS regression now identifies actual live descriptor cohorts,
proves which held source and query owners close, and consumes each injected
close before returning `EIO`. It no longer depends on compiler return addresses.
The qualified normal cohort passed its query-FD, held-child-FD and directory
close cases, recovery checks and no-retry assertions. The same fixture also
passed after compiling it at `-O2 -g0 -UNDEBUG` with strict GCC 14 warnings,
linked against the unchanged normal `-O0` SDK. This is an optimized-fixture
check, not qualification of an optimized product build. CTest now registers
`native_sync_resolution_posix_close` on Linux.

## Coherent macOS development race run

The 418-file development snapshot (manifest
`1ec62808999f485488403f0691e1a360a4d783bd9f0f38deafd45d04c6f58e5a`)
was rebuilt with LLVM 23.1.4, matching TSan instrumentation on all 171 C/C++
translation units, and the separately qualified corrected Darwin runtime
`ba79ff2e55b670221abbcd28d5becef30eae9b56b9f77d9a6a9673f4e356eae2`.
The clean 217-step build took 312.17 seconds; all 50 CTest entries ran in
55.14 seconds. Loader output proves that exact runtime was used, with no race
warnings or runtime CHECK failures.

The suite result remains **43/50 PASS**, with seven failures: native regular
metadata publication, regular metadata, lifecycle, C Tree copy, C Tree KeepBoth,
reviewed Tree execution, and changed-receipt preview. The latter observed
`journal_scope.ancestor_changed` during its precondition; an isolated run of
the same binary subsequently passed all 153 changed-receipt checks. The
original failure is retained and its external cause is not established.
The remaining publication/receipt failures still block release. No failing
entry was skipped or converted into an expected pass.

This snapshot includes the first terminal-drain fix but predates the subsequent
journal-owned Root propagation correction and new Tree own-effect integration.
It is neither a stock-runtime pass nor qualification of those later changes.

## Native copy terminal ownership and persistent OOM

The worker now explicitly consumes its base native source after commit/source
retirement decisions, retaining only a closed shell until borrowed stream
callbacks are destroyed. Protocol exceptions and finalization failures use
fixed scalar diagnostics until native cleanup has run. Both native journal
adapters close file and parent handles even if validation or diagnostic
construction throws, and cache the first native failure without allocation.

Qualification first exposed two Linux source-close EIO plus persistent-OOM
failures: source and writer closed, but the journal remained open at terminal
return. The journal correction passed all eleven original cases and eleven
standalone flush/close controls. Review then found that this probe installed an
outer Root observer absent from the basic C worker. Removing it reproduced four
missing-Root-error failures. A genuine journal-owner bridge now records the
native error directly in its retained Root, before any diagnostic allocation.

The corrected Linux normal cohort passed **34/34 controls**: twelve without an
external observer, plus the twenty-two retained observer/journal controls.
Source, writer and journal close once at terminal, before destruction; reused
numeric descriptors survive repeated advance/destruction. Root preserves source
EIO before the first denied allocation and preserves an earlier ENOSPC when
present. Root's own final drain is tested after consumer references are released.
The NativeCopy fixture deliberately supplies a no-op metadata phase to isolate
base-source finalization; it does not qualify metadata replay or native Move.

A fresh, consistently instrumented GCC 14 ASan+UBSan cohort subsequently
passed **36/36 focused cases in 3.99 seconds**. All 132 product and five test
translation units were built with matching headers and instrumentation; the
clean build took 1,016.47 seconds. No normal/old SDK objects or sanitizer
suppressions were used. Independent clean and intentional heap-overflow controls
verified the actual runtime and the custom allocator test boundary. This does
not qualify a whole Tree or the later Batch/Legacy candidate.

The regression fixtures are registered with CTest, including separate portable
protocol/finalizer OOM tests that consume real native pipe handles. Linux probes
require an explicit fixture root and inspect its actual ext4/XFS/Btrfs provider;
unknown or mismatched providers fail. Windows normal, matching sanitizers, and
subsequent pending-batch/legacy-metadata drainage remain separate gates.

## C ABI error reporting under allocation exhaustion

The basic C error copier now accepts a non-owning string view. Previously an
invalid directory argument could construct an owning C++ string inside its
`noexcept` error handler. The Linux normal static-wrapper regression reproduced
termination (exit 3) under persistent C++ allocation failure; the corrected
wrapper returns `INVALID_ARGUMENT`, reset output handles and the scalar error
without attempting a C++ allocation. The underlying frozen SDK and other
wrapper objects retained their hashes. Its explicit C allocation remains
fallible, with a null diagnostic pointer permitted. This focused result is not
a final SDK or sanitizer qualification. CTest registers `c_api_error_oom`.

## Prepared-batch terminal drain

Cancellation previously left the native owners of prepared, unstarted entries
open until batch destruction. A regression with three real native pipe handles
reproduced the missing finalizers against the prior SDK. The batch now uses a
private I/O-only finalizer to drain every prepared entry before terminal return,
without running validation, journal transitions, copy, publication or retirement
for pending entries. An uncertain/retained-source result stops later mutation;
clean unstarted rows remain Pending. Terminal advances neither close again nor
retry diagnostic allocation.

A fresh coherent LLVM 23.1.4 build with the matching corrected Darwin TSan
runtime passed **10/10 focused CTest entries** in 4.54 seconds. The 128-step
selected-target build took 277.48 seconds. Six new batch controls cover clean
cancel, native close error, provider exception, persistent C++ OOM and uncertain
first-entry outcomes; portable OOM, metadata-review and I/O-finalization
regressions also passed. Exact source/runtime/output hashes are retained.
This qualifies the batch composition and its real-handle regression. Native
multi-item copy/metadata integration and final cross-platform qualification
remain separate gates.

## Hard-linked source fixture corrections

The permanent hard-link fixture uses bounded wide Windows environment queries,
extended native paths and exact UTF-16 names. Native normal checks passed on
NTFS and ReFS: 302 with the workstation path policy, 292 with the default policy,
and 55 each for explicitly configured UNC refusal. Unreachable, missing or
wrong aliases remain UNQUALIFIED rather than passing. The same fixture compiled
with strict GCC 14 warnings and passed 114 checks on actual Linux ext4 against
the unchanged earlier read-only hard-link SDK.

A previous fixture asserted that every rapid link-only `2 -> 3 -> 2` cycle must
change the timestamp. Its ReFS failure and native diagnostics are retained:
actual metadata events can share ChangeTime. The corrected deterministic
negative test opens the real third alias, verifies identity, appends a byte,
flushes and closes it, removes that alias and observes link count two again.
Both source verifiers must reject the actual size/content change; both surviving
aliases contain the expected bytes. No sleep or timestamp forcing is used, and
always detecting an intermediate link-only ABA is not claimed. Windows
[ChangeTime](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_basic_info)
and [timestamp documentation](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times)
define time observations rather than a distinct event counter. Source observation
is not an enforced mutation freeze. Writable target and private-journal alias
refusals remain required.

## Remaining gates

- Integrate and qualify postorder directory metadata replay and bounded
  regular-file metadata execution against the exact reviewed evidence.
- Qualify integrated base-source, legacy metadata and pending-batch drainage on
  Windows and with matching sanitizers, preserving Move retirement ordering.
- Qualify Windows named conflict resolution and all-stream admission.
- Qualify the final integrated revision and matching sanitizers across the
  recorded ext4, XFS and Btrfs layouts.
- Retain the macOS strong-publication failures until a suitable native
  primitive is available and qualified.
- Qualify the final coherent SDK with its installed C consumers and matching
  sanitizers before changing frontend pins or release tags.

The proposed ckgit runner remains disabled. Its observed job bind topology
currently fails the native ancestry guard, and the installed runner lacks
project-specific job admission. A configured workflow alone is not running CI.
