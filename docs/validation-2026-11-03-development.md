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

## Real legacy metadata and multi-item batch cleanup

Legacy preservation now explicitly drains native channel readers and releases
its operation-owned held source before terminal completion. Its copy-batch
binding supplies that drain to the common native finalizer. Cached failure
reporting retains scalar state and propagates allocation failure after cleanup
without an allocating empty-string fallback.

A fresh coherent GCC 14 normal build includes the newer Tree/seed request
layouts, restored cleanup-observer declaration, batch drain, legacy drain and
C error-view fix. All **28 selected CTest entries passed in 5.87 seconds** after
a 397.46-second, 162-step build, with assertions enabled and source hashes
unchanged. Eleven real three-file legacy batch cases include pre-start and
started cancellation, actual source/journal consumed-close errors, persistent
C++ OOM, prior Root error precedence, stopping later mutation after an uncertain
first item, complete copies and binary xattr replay. Pending journals remain
unchanged; native source/journal/staging handles close before terminal return;
repeated terminal polling does no native I/O or allocation retry, and reused
descriptors survive destruction. Caller-held directory cursors are permitted to
remain; Root is finalized after consumer references are released.

The same coherent run passed portable batch/OOM checks, C error OOM, hard-link
source capture, metadata review, native resolution and its C/consumed-close
regressions, Linux mount witnesses and ELF exports/interposition. This is
focused Linux ext4 normal qualification, not a full integrated Tree, Complete
security, Windows or matching sanitizer result for the later combined revision.

## Receipt-bound Windows native Tree integration

The worker now binds a private execution seal to the immutable reviewed receipt,
comparison, policy, journal operation and genuine held roots. Per-row permits and
an internal own-effect ledger cannot be supplied as caller facts. Completion
proofs require whole-tree verification and native drainage; they remain
worker-owned historical evidence, never fresh execution, session or baseline-CAS
consent. A different row, receipt, revision or Tree cannot reuse them.

Native independent target readers are prepared before restrictive security and
final timestamps. Directory enumeration opens a fresh native cursor after child
and ADS effects. Actual target observations, bounded metadata budgets and source
bookends drive postorder verification; source identifiers are never copied into
target observations. Comparison and native replay request layouts changed, so
all C++ consumers and affected implementation units require a coherent rebuild.

The isolated Ordinary/Original Windows cohort passed **8,534 NTFS checks in
458.03 seconds** and **8,694 ReFS checks in 697.39 seconds**. It covers strict
regular-file copying plus created and merged directories, ADS, progressive
metadata, target readers and sealed completion. The same executable passed
**4,213 NTFS / 4,389 ReFS adversarial checks**: changed source before staging,
foreign target mutation, cancellation after directory creation, and actual
journal-close failure with and without an injected diagnostic allocation failure. None of
those failures may issue completion proof. These are native normal results;
the frozen cohort precedes the later common Batch/Legacy cleanup fixes.

The Complete/Original derivative enabled and independently queried genuine
SeSecurityPrivilege. It passed **8,975 NTFS / 9,119 ReFS checks**, with binary EA,
ADS, a protected read-only DACL, success/failure audit SACL and Medium/NoWriteUp
mandatory label populated. Resource attributes, scope, process-trust label and
access filter were queried empty. Populated roundtrip coverage for those last
four classes is not claimed. CurrentCaller and final combined SDK/sanitizer
qualification remain pending.

The separate fixture-boundary derivative passed **333 checks per filesystem**
with wide environment APIs, a non-ASCII and unpaired UTF-16 root, an extended
root longer than MAX_PATH, canonical V: development-root checks and a memory-only
wrong-drive negative. This did not rerun the expensive Tree cases. The permanent
CMake entries preserve that distinction: native Windows-only tests, measured
new-test deadlines, and explicit opt-in
`CK_CORE_FS_TEST_PRIVILEGED_METADATA=ON` for Complete security cases. The ordinary
and Complete target-reader CLI entries are now separate; their small dispatch
change and the Complete fixture's wide setter replacement still need the next
Windows derivative run. Non-Windows no-op entry points are not registered as
qualification.

The native Copy source-close regression is also permanent. Its earlier frozen
product cohort passed **28/28 normal and 28/28 matching MSVC ASan cases**. Native
NTFS/ReFS handle failures, scalar first-error preservation under persistent OOM,
exact-once cleanup and handle reuse are covered; actual native Move publication
remains a typed refusal. Neither this earlier result nor the isolated Tree
results qualify the final combined revision.

## Linux native reader, layout and Complete security packets

Fresh descriptor-based enumeration fixes stale root listings and journal-ledger
loads. The read-only observer opens a new description through the genuine held
directory, checks native identity and version, and closes it under the native
error observer. Ledger loading now records its version checkpoint before opening
the enumerator. Actual ext4 and top-level Btrfs controls passed repeated
inventory, newly inserted entries, insertion during enumeration, changed-state
refusal, fresh retry and consumed `closedir` EIO. The counterfactual old observer
missed two real entries and the old ledger loader returned an empty result after
insertion. Darwin helper runtime qualification remains pending.

A valid non-root Btrfs mount layout and unsupported mount attributes now produce
typed Unsupported results. Malformed root strings and buffers remain failures.
Native top-level/non-root Btrfs cases and eight wrapped kernel-reply controls
passed. This does not enable arbitrary Btrfs subvolume layouts.

A separate three-file Complete issuer packet appends
`LinuxPersistentSecurityV1` without changing existing enum ordinals, structs,
vtable layouts or the public C ABI. Its private native proof binds exact policy,
owner identities, ACLs and xattr bytes, genuine initial-user-namespace evidence,
actual kernel LSM IDs, filesystem and inode/storage classes. Public caller-made
evidence or modified snapshots cannot issue that proof. Legacy issuance checks
live access time; progressive issuance binds its private pre-read sample.

The qualified scope is **ext4 inodes without birthtime, with capability-only LSM
and genuine initial-namespace CAP_SYS_ADMIN**, plus explicit policy permission
for privileged metadata. Other LSMs, IMA/EVM, unknown classes, birthtime-bearing
inodes and unsupported storage policies remain refused. No Ordinary fallback,
security-setting change or automatic elevation is used.

Normal and matching ASan/UBSan cohorts passed real Original and CurrentCaller
roundtrips with ACL, binary user/trusted xattrs and file capabilities. Additional
controls passed forged-atime/owner/policy/value rejection, full-identity-mapped
child-namespace refusal, missing-capability refusal, protected-integrity refusal,
SGID denial before effects and a genuine SGID roundtrip with CAP_FSETID. Extra
proof-reader close EIO preserves the first scalar error and consumes each owner
once; the borrowed source remains usable. Existing unprivileged progressive
capture tests also passed. Fresh normal/sanitized builds compiled 111 translation
units in 304/580 seconds; final affected-unit rebuilds took 21/53 seconds. Strict
POSIX/test compile checks passed.

The Linux Full fixture is a build target, not an unconditional unprivileged
CTest. It requires isolated native fixture setup followed by the recorded
restricted worker credentials. The frozen source and runtime receipts precede
the final Main/target-reader merge; combined Tree, SDK and sanitizer gates are
still required.

## Additive cached manual-name feedback

The new C getter keeps all existing v1 layouts unchanged and returns a fixed
112-byte cached record. Core assessment reports the required Incoming/Target
side, side mask, actual selected decision, qualified source preservation and
retention, plus separate capability and submitted-selection reasons. Unknown
strict source metadata blocks Target naming even if retention is available.
The assessment command ID distinguishes old cached feedback from a newly queued
review; stale/invalid requests clear the full output.

The isolated normal GCC14/ext4 cohort passed three registered tests, strict
installed C11 linkage and the ELF export audit. Actual worker reviews reject
side mismatches without a receipt and accept a valid Incoming review. A thousand
cached polls run with polling-thread allocation rejection and filesystem-call
traps armed; all counters remain zero. Generation, row, choice and null-job
negative calls preserve typed failure and zero output. The genuine-retention
plus strict-unknown-source combination is a pure core policy test; no Windows
native execution claim follows from it. The native test cancels and drains
without publication. Windows, Darwin, sanitizers and the final integrated SDK
remain separate gates. Private Facts/item layouts changed and require coherent
recompilation of every affected translation unit.

## Linux target-reader lifetime and combined integration checkpoint

The native Linux reader authenticates separate source-proof policy/shape and
actual target identity, mount, kind, size and version. Existing-directory
factories still require proof about that genuine held directory. Capture clones
use independent read-only O_NOATIME descriptions; insufficient owner/FOWNER
rights return Denied without a timestamp-mutating fallback. Darwin retains its
original descriptor-clone route.

Each real clone reserves its own native handle and metadata lease before open.
An explicit private counter tracks clones even after the original reader is
finished. Native descriptor/DIR members close before their budget and lifetime
fields are released. Target enumeration uses descriptors prepared before final
security, with serial native restart: a mode-000 target remains observable.
EOF releases enumeration position while retaining the exhausted cursor's actual
native handle and budget until destruction.

The isolated native component passed different-inode regular/directory cases,
actual capture-clone lifetime, budget exhaustion/recovery, restricted late
enumeration, pinned exhausted cursors, cancellation and foreign-brand refusals.
Eight actual close/fault modes passed, including source/clone EIO, persistent
C++ allocation denial, prior Root error preservation, destructor ordering and
FD-reuse/no-retry checks. The last affected platform rebuild took 14.37 seconds;
it is incremental component evidence, not a fresh combined SDK.

A fresh coherent 439-file Main cohort compiled 172 steps in 645.80 seconds.
The initial selected run passed **37/39** entries. One registration omitted the
positive reader fixture's required root argument; rerunning the unchanged,
hash-verified binary with that argument passed, and the registration is fixed.
The remaining Tree failure is real: generic metadata capture rejects link count
zero on Linux's genuine anonymous staging target. The provider must authenticate
that specific read capability before capture may accept zero links. Ordinary
unlinked sources must remain rejected. The failing run is retained; Linux Tree
execution is not promoted by these component results.

The current merged POSIX provider, Tree and fresh-observer sources also passed
Darwin syntax compilation in 8.02 seconds. This is compile-only coverage, not a
macOS native execution result. Strict ckdocs built all 17 then-current pages;
newer name-feedback documentation requires the next site validation.

## Coherent Windows legacy batch and installed C checkpoint

A fresh MSVC x64 normal SDK compiled 157 steps / 141 compile commands in
1,545.53 seconds using matching `/MDd /Od /Ob0 /RTC1 /Zi /EHsc /GR /utf-8`
inputs. Product/header hashes match the earlier `51e7835` cohort; newer name
feedback, reader-clone, CurrentCaller and hierarchical-session changes are not
included. No prior v2 objects or SDK archives were reused.

All ten actual three-item legacy batch modes passed on **both NTFS and ReFS**
(20 total). They exercise pre-created journals and retained ADS read handles,
pre-start and started cancellation, actual source/journal close errors,
persistent allocation denial, prior Root error precedence, stopping later items
after an uncertain first item, and successful payload/ADS/mtime/identity/owner
verification. Pending journals stay unchanged; later items stay unread and
unpublished. Native handles drain before terminal return, repeated terminal
polls do no I/O/allocation retry, and separately owned events reuse the retired
numeric handles without being closed again.

The same frozen SDK passed nine portable Batch/Execution/C API OOM entries,
the earlier 28 source-close gates, native metadata/stream/source-version checks
and 302 hard-link checks per filesystem. Categories overlap and are not an
additive test count. The installed strict C consumer and all **170 declared C
exports** passed. Earlier fixture-only failures are retained: direct NT import
forwarding, exact legacy operation tag, pending-state expectations under shared
Root failure, and TokenUser versus actual TokenOwner.

The regression is now a permanent Windows CMake target. Its misleading inherited
header comment was corrected; executable test logic matches the frozen
qualification. Matching ASan and the final combined revision remain pending.

## Read-only hierarchical Session lease prerequisite

Native hierarchy readers may now borrow the existing Session's genuine roots,
locks and generation-bound epoch. Caller-defined backend subclasses, value IDs
and handles cannot mint the private native brand. Bindings retain exact native
components, inspect and revalidate parent/child membership, and return descriptive
metadata without exposing writable handles or mutation/CAS authority.

Session refresh, recovery, commit, finish and destruction revoke registered
reader aliases before generation advancement or native lock release. Revocation
clears the Session pointer before callbacks, drains every registered consumer
without allocation, and preserves the first scalar close error. Allocating
diagnostics run after native drainage. The original borrowed journal-root
lifecycle remains the caller's responsibility.

The qualified prerequisite packet passed **346 MSVC Debug checks each on NTFS
and ReFS**, plus **706 Linux helper/OOM, 5,102 Session and 368 Resolution checks**.
Actual persistent allocation denial and consumed native close failures cover the
selected failure sites; they do not establish all-allocation-site OOM coverage.
An independent Windows source review found no additional issue. The unsafe older
675-check packet, its allocating noexcept fallbacks and failed Debug traces are
retained as superseded evidence rather than counted as success.

The integrating branch preserves the three directed implementation units and
native tests, removes the fixture's arbitrary UID-1000 restriction while retaining
its non-root requirement, and makes epoch-ID exhaustion nonwrapping. These small
derivatives and the new private SyncSession layout are undergoing a fresh
coherent combined build. This prerequisite does not implement recursive mutation,
Tree-to-Session completion relay, nested durable ledgers or physical power-loss
qualification.

## Directed static-library ownership

Actual native staging and a standalone Core consumer reproduced a reverse
Engine-to-Platform dependency on the native Root consumer-failure bridges. The
archive audit identified twelve reverse references. Native workers now reside
in Platform, with portable metadata digest/cleanup/budget primitives split into
Core units. Held-child replay and native session-root acquisition are separated
from their portable implementations. Existing dependency declarations and class
layouts remain unchanged; no repeated archives, archive groups or whole-archive
flags are used.

The isolated GCC14/ext4 normal packet passed **11/11 selected native tests** and
**4/4 installed Core/Platform/Native/C API consumers**, including actual anonymous
staging publication and its mandatory unprivileged/thread-FD controls. Link maps,
archive membership and the runtime path to that exact installed `.so.0.5` were
verified. The initial fresh baseline took 674.51 seconds; the ownership correction
rebuilt in 88.57 seconds. A stale candidate input timestamp exposed duplicate
moved helpers during the first attempt; all changed inputs were then marked dirty
and rebuilt before qualification. Failed attempts are retained.

The integrating branch merges these ownership hunks with its newer Session epoch
changes. Windows, Darwin, sanitizers and the final combined cohort remain pending.

## Windows Caller ownership and prepared-reader consumers

The frozen 13-file Windows packet adds a native effective-token ownership
observation before target effects, genuine independent target capture for
CurrentCaller directory replay, and policy/ownership-normalized postorder
comparison. Standalone Caller replay without that native observation route is
refused. TokenOwner and TokenPrimaryGroup are queried independently of the
source and destination's old owner; the library does not adopt target-before
ownership as caller identity.

Native ordinary/Full reader cases passed **5,903 / 5,812 checks per filesystem**
on NTFS and ReFS. Real duplicated base/stream/cursor handles each reserve their
own budget and private consumer lifetime. Explicitly finishing the original
source cannot hide a live clone. Finish refuses until consumers drain, while
exhausted enumeration position can release independently of actual handle
ownership. Destruction consumes native owners before releasing leases and
forwards cached first close errors.

Full Tree Original passed **8,975 NTFS / 9,083 ReFS checks** and Full CurrentCaller
passed **9,079 / 9,187**. A focused different-native-owner control passed
**2,409 / 2,445**: source and merged target-before owners differed from TokenOwner,
final target owner/group matched independent token queries, and source security
bytes/main content remained unchanged. Different-primary-group remapping was
not independently established. Resource/scope/trust/access-filter classes were
queried empty rather than claimed as populated roundtrips.

The regular metadata worker also passed persistent C++ allocation failure
**after native closes**, preserving its POD terminal state, exact close error,
zero handle reservations and no-I/O cached failure. No MSVC proxy allocation was
skipped. Whole-Tree persistent OOM remains unqualified. The three updated legacy
CLI forms passed on both filesystems.

All component implementation bytes were frozen with guarded source hashes.
The final Tree/name-feedback rebase and Main's newer Session/layer/anonymous
capture changes require a coherent combined SDK rebuild. These receipts are
normal Windows results, not matching ASan qualification. The integrating CMake
adds explicit privileged Caller and different-owner test entries.

## Combined Session and library-layer checkpoint

The coherent 455-file Session prerequisite cohort compiled 183 steps in
736.21 seconds and passed **43/43 selected tests in 22.93 seconds**. It includes
the new private Session layout, nonwrapping epoch IDs, ordinary-user portable
fixture, native persistent-OOM lease regression, existing Session/Resolution
checks, name feedback and target-reader cases. Linux strict Tree activation and
the anonymous-target correction were separate unqualified candidates.

A controlled owner-managed layer derivative retained its baseline source/archive,
output hashes and test results before overlaying nineteen changed/new files.
No public or private headers changed during that layer overlay. All moved native
worker units rebuilt in 92.62 seconds and **45/45 tests passed in 32.00 seconds**,
including real native staging and the archive dependency audit. A fresh install
then passed **4/4 independent Core/Platform/Native/C API consumers**; the C facade
resolved to the exact installed runtime. Runtime SHA-256:
`0c90c7602ebe63d9f156247408f8361b817a49bdf878942deaa40d701abd172b`.

Darwin compile-only checking passed for eleven coherent Session/lease/layer units
in 16.04 seconds. No native Darwin success is inferred. The later Windows Caller
and anonymous-target packets still require their own combined rebuilds; these
results do not qualify hierarchical mutation or the next SDK revision.

## Remaining gates

- Qualify the final combined postorder Tree and bounded metadata workers on
  Windows, Linux and macOS; retain explicit unsupported native primitives.
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


## Additive nested-path ledger, corrected Windows cohort

The four-file ledger packet adds an explicit hierarchical encoding and native
`create_hierarchy` factory. Existing flat encoding retains its 444-byte golden
fixture and SHA-256 `f7ad55d2f5ebb97126a667c6d4d008a39a1b17309d241625a5152e8f090ae1cd`.
The new schema bounds exact native component chains, records file/directory
kinds, requires ancestor and retained-artifact parent closure, and rejects
mixed schemas within one journal. Ancestor alias rejection compares the raw
object identifier independently of optional generation, preventing a different
generation field from disguising a self-ancestor. The original failing cases
and corrected regression controls are retained.

The corrected MSVC normal cohort passed 3,071 codec checks and 132 independent
controls. Each of NTFS and ReFS passed 27 native storage checks, 76 exact-name
journal/schema checks, and 76 long-path checks. The actual parent paths were
429 and 397 UTF-16 units. Tests used genuine private Roots, native append and
flush barriers, reload/reopen, exact unpaired UTF-16 and trailing dot/space
names, V1/V3 coexistence, and mixed-schema refusal. Reachable localhost UNC
storage was refused by the native driver qualification gate; it is a negative
control, not UNC persistence support. No power-loss experiment is claimed.

The clean SDK used 110 observed compile commands and took 775.98 seconds;
the recorded Ninja timing and CPU/affinity evidence explain why its duration
cannot be compared directly with the earlier larger Debug cohort. Corrected
source manifest SHA-256:
`dd39b0f4cdab6c986a9ab73edefb28e803add5aa2dc00eb9a4bb3316610ebe92`.
Receipt SHA-256:
`908ce39e49ea5db6d48a4052a55e42b1ad0729c7c238e8b66cef035e25d09f17`.

These records describe intent. They confer no native tree execution, Session
ownership, convergence, or baseline-CAS authority. That relay remains a separate
integration and runtime gate. Matching final combined and sanitizer results
remain pending.

The imported ledger implementation and both permanent fixture translation units
also passed Apple Clang C++20 syntax checks in 5.81 seconds. This is compilation
coverage only; no Darwin native persistence or final combined SDK result follows.


## Linux anonymous-target capture and reviewed execution correction

The private Linux adapter now issues an anonymous-target capability only from
its genuine writable anonymous creator. Read-only capture views retain that
capability across native clones. It binds identity, mount and adapter scope;
each capture independently requalifies current policy and reads the held
native descriptor to compare identity, kind, link count, size and ctime with
the supplied facts. A zero-link ordinary source or caller-created entry cannot
substitute for this proof. Windows and Darwin retain a typed refusal for this
Linux-only capability.

Existing-directory metadata verification no longer requires rename authority
for that metadata-only step. Rename, replacement, retention, deletion, Root,
membership and version checks retain their existing requirements. Postorder
replay preserves unknown stream coverage instead of inventing a known zero
from an empty channel vector. The Linux reader/anonymous-target implementation
now enables the previously guarded regular-copy and existing-directory paths;
new POSIX directory creation remains Unsupported.

The isolated coherent 439-file GCC 14 Debug candidate passed **8,685 Tree
checks**, covering regular copy, existing merged directories, source changes,
foreign target effects, native journal close EIO, one injected diagnostic
allocation failure, and new-directory refusal. Target Seed, all eight native
reader/clone/cursor failure cases, ordinary metadata capture, and 114 hardlink
checks also passed. Its full build took 1,026 seconds and stopped at the old
archive-layer failure; the relevant targets linked and ran. The later library
layer fix is independently qualified above, rather than retroactively changing
that failed full-build result.

This merge rebases those narrow changes over the newer layer, Session lease,
name-feedback and Windows Caller work. Full anonymous capture has not yet
passed: the ordinary runner lacks initial-namespace authority, while the root
attempt reached the precise ext4 birthtime-preservation limitation. A separate
no-birthtime ext4 fixture is being qualified. Source-only follow-ups order the
security-proof lease before its held source and tighten the optional Full test
to known provider gates, exact positive opt-in and successful cleanup. These
follow-ups and the final combined SDK require fresh runtime qualification.

The frozen baseline-to-final packet manifest is
`09718b2c7cb99cf53a9cac51ddf6bb18ffead5c68b3ab462a4033df6da00c98e`.
No existing SDK or later headers were mixed into that candidate's runtime.


### Follow-up: Full anonymous capture on no-birthtime ext4

The separate initial-user-namespace/private-mount-namespace fixture now passes
with a real ext4 inode-size-128 filesystem, which reports no birthtime, and
`CK_FS_REQUIRE_FULL_ANONYMOUS_CAPTURE=1`. The genuine anonymous zero-link view
completed Full metadata capture and explicit drain. The tightened test requires
both presence and a true drain result; the affected test rebuild/relink took
eight seconds. Source manifest:
`f54fc79f53de0c5d6fa33a718aad1a0ecc0470c0a1da85d902e1a17829da0260`;
executed binary:
`32022f11f52e7e372d7b2c82b43c1d1e862565eb3f31d71d82659057b9e8ca20`.
The verified executable was held across execution. The fixture unmounted and
detached its exact owned loop device, then removed its disposable image after
retaining hashes and logs. No host/global filesystem configuration changed.

This closes the anonymous-target **capture** gate for that narrow provider
scope. It does not qualify Full Tree publication, the next combined revision,
other ext4 inode formats, or another security environment. The existing
birthtime and unsupported security-class gates remain in force.


## Session baseline readers and native teardown close failures

A native regression reproduced false acceptance of baseline bytes when their
read descriptor closed with an error after the Available result was built.
Transient baseline consumers now drain inside a Root-bound operation scope
before read or publication success returns. Their first native close failure
enters the Root's fixed-size latch before diagnostics, callback failures, further
cleanup, or allocation failure. Writer ownership is consumed before close and
never retried. Terminal directory and Windows volume-lock close errors retain
the same first-error ordering. Borrowed Roots remain owned by their Session.

The exact three-file packet passed **384 new native checks plus 5,100 existing
Session checks on Linux ext4**, and **406 new plus 5,367 existing checks on
ownership-enforcing APFS**. Native controls consume the actual close, then
report EIO; persistent allocation failure begins after that consumed close.
They cover normal and oversized baseline reads, flushed writers, directory
teardown, first-error precedence, lock release, and descriptor reuse without a
second close. The original-code control fails the baseline-acceptance assertion.
This is native error/ownership testing, not hardware or power-cut testing.

The fresh GCC 14 Debug SDK took 411 seconds/132 steps and its corrected fixture
rebuild took two steps. The matching Apple Clang Debug SDK took 245.56 seconds/
130 steps; APFS writer tests retain the required F_FULLFSYNC path. Strict
POSIX compilation passed with recorded inherited warning-category exclusions.
Packet SHA-256:
`7b04e0fac5845607db4cf54186fee05273a8eb453552a1b183c2f5198fcddd7c`;
frozen source manifest:
`bb75a12b23d21e87a1d46e0aa2d96823d98047431d9ea79705552c15ed05dc31`.

The Windows implementation and native fixtures are present but **unqualified**:
SSH timed out before any build launched. Matching sanitizer and combined SDK
qualification also remain pending. The bounded review found no additional
concrete overlap-lock bypass or durable-intent ordering defect.


## Full Linux normal cohort and cancellation fixture reconciliation

The frozen `2fffc30` cohort contains 469 files. Its fresh GCC 14 Debug/O1/g0
build compiled all **209 configured translation units in 283 steps**, taking
577.56 seconds. Every configured object was observed in Ninja, with output
timestamps within the recorded build interval. The empty output directory,
compiler commands and source hashes prove freshness; no compiler cache launcher
or reused object was found. Earlier selected-build timings are not the same
workload. The complete default CTest run was **126/133 PASS**, with seven
failures retained in its original XML/logs. This cohort is not fully qualified.

One failure was an obsolete cancellation-fixture expectation: after proving an
anonymous writer's failed flush and NeedsReconciliation, it still expected Root
finalization success. The corrected fixture requires the Root's native POSIX
EIO and `content.*` operation to remain sticky across repeated finalization,
with no repeated writer flush or destination publication. The original fixture
failed; the corrected fixture passed **51 native checks** against the exact
unchanged frozen SDK headers and three static archives. Source and archive
hashes were verified before and after; no production source or original SDK
was modified for this comparison. The other six tests remain under review.


## Verified retry: reader drain before native and C terminal success

The original production C-worker control reproduced Complete/code-zero after
its review reader's consumed close failed. A separate allocation-failure
control replaced a native journal close error with an Adapter error. Retry now
provides NativeCopy with an explicit metadata/read-owner finalizer, drains
source and prefix-candidate views, and preserves the first native error in a
fixed POD before publishing terminal state. The worker reads that POD even
when constructing an error Observation throws. Its destructor uses the same
idempotent drain, and the raw borrowed staging pointer is removed. Progress and
attempt existence remain available as immutable cached values after drain.

The matched Linux AArch64 GCC 14/O1 normal cohort passed **12 production C-worker
cases**, **two C++ abandonment cases**, and the existing verified-retry suite.
Cases cover success/cancellation, consumed source/candidate/base-reader and
journal close failures, persistent allocation failure, descriptor reuse with
no repeated close, and preservation of prior Root ENOSPC. No external cleanup
observer assists the production C worker. The affected SDK rebuild took
12.13 seconds and the strict native probe build 12.18 seconds. All qualification
stages passed; original failing controls remain preserved.

Packet manifest:
`ec311a016bae26cf42d93766c74877d9e3e832b4af0d43e05c53a4bbcb2baeb6`;
frozen source manifest:
`7bbbd73a9f53f659bcedeb3394ff1e0b953ababfe602f7524bfe2263afdf836d`.
C ABI v1 layouts are unchanged. The private C++ retry class layout changed,
requiring coherent rebuilds of its implementation, C wrapper and consumers.
Permanent Linux CTest entries register all fourteen modes. Windows, sanitizer
and final combined qualification remain pending. Genuine private-Root overlap
admission is a separate implementation increment, still under qualification.


## Verified retry: private-Root admission and first error across Roots

Retry now admits both genuine journal Roots against the held source,
read-only prefix candidate, and destination namespace before opening the
original journal or creating an attempt. Legacy addresses are adopted once;
subsequent I/O uses those held owners. Scope and membership are rechecked during
execution and before publication. Only privately adopted Roots are finished
by retry; passed capabilities remain borrowed. No global active-Root registry
or exclusion against arbitrary external writers is claimed.

A separate drain amendment preserves the first Root error already observed
by the job when the other Root later fails. Its original-code control
reproduced earlier attempt-Root ENOSPC being replaced by later original-journal
EIO. Early explicit finish also revokes subsequent approval/advance authority.

The combined Linux normal packet passed **40 native cases and the existing
retry suite**: 16 drain/lifecycle cases, 18 scope cases, and six actual bind
aliases in private user/mount namespaces. It covers both Roots, source/candidate
hard links into private state, post-review topology changes, valid external
hard links, and address adoption. Persistent allocation-failure and descriptor
reuse controls retain native error and no-retry checks. Namespace setup exit77
is unqualified/failure, never a skipped pass. The affected rebuild took
13.35 seconds against the preceding comparable 12.13-second drain rebuild.

Packet manifest:
`c519aa217addf644437e767bca911394f69e330aa587a3e6e9d559594c51d1fb`;
qualified source manifest:
`0bd297d29db41d2ea09610b16f788cdbc74b2aa318813b59870cd199d3a71cc8`.
Public C ABI v1 is unchanged; the private C++ retry layout changed again and
requires rebuilding all dependent translation units. Windows, Darwin,
sanitizers and the final combined Main revision remain unqualified. A separate
source review of the Root pending-first-writer protocol is still in progress.


## Reviewed-Tree positive fixtures use qualified native contracts

The remaining six full-normal failures were obsolete fixture assumptions, not
evidence that the production creator guard should be relaxed. Mutation-positive
fixtures now select strict Ordinary preservation with Original ownership.
Linux precreates destination directory skeletons, retaining every source row
and byte/zero-length assertion; Windows keeps native-created-directory positive
cases. Explicit-loss scenarios retain their own original policy. The permanent
Linux native creator-refusal control remains unchanged.

C stale tests require an accepted execute command before checking execution
rejection. Their preexisting destination skeleton, including directory mtime
and ctime, must remain unchanged. All six C++ substitution variants remain.
The partial-progress ancestor test first completes a regular copy, substitutes
an existing destination ancestor, then requires exact Changed/MetadataChanged
`reviewed_tree.root_observer_changed`, NeedsReconciliation, partial/recovery
flags, retained completed payload and no nested publication. Main's writer
cancellation test is byte-identical to the preceding correction.

The isolated fixture patch passed all **seven C API scenarios**, the full C++
bundle (**796 checks**), changed receipts (**159**), Compare (**88**), private
scope (**353**), progressive metadata (**3,135**), explicit loss (**1,852**) and
cancellation (**51**). The unchanged native positive/creator-refusal binary
passed **8,685 checks**. Two test translation units compiled/linked in 8.73
seconds. All 158 product headers and four library hashes matched the frozen
`2fffc30` SDK before and after; ldd verified the exact C runtime. Original and
intermediate failures are retained.

Fixture patch SHA-256:
`bf8a3ba33a65aae3ff556007810da201c696a902960cbec9b6a7da1447d99861`.
No production code was changed in this increment. Windows runtime, the later
Session/retry changes and the final complete suite remain outside this receipt;
those require a coherent subsequent qualification run.


## Installed layer consumers and Windows exact-path fixture helper

The qualification script now configures, builds and runs the installed Core,
Platform, Native and C consumers after its original C consumer. It propagates
the same configuration/instrumentation options and uses the explicit native
fixture root, or the task temporary root when none is specified. The Windows
clients use wide entry points, exact UTF-16 directory addresses and Windows
NativeName values; their POSIX branches remain. The fixture helper retains
extended DOS/UNC namespaces through validation, file creation and cleanup.
Windows output no longer claims the Linux-only anonymous-publication branch.

Against the frozen `ac03959` MSVC Debug/MDd SDK, the original C consumer passed
1/1 and all four installed layers passed 4/4. Eighteen independent NTFS/ReFS
controls covered Unicode, unpaired UTF-16 and paths up to 483 units. The final
helper delta additionally passed **12 actual-helper controls** with 366–377-unit
Unicode/raw UTF-16 parent paths and verified cleanup. Exactly two consumer
objects and two executables rebuilt in 36.25 seconds; SDK objects, DLL/library
hashes and all 155 installed headers remained unchanged. The archive dependency
audit and all 171 declared exports passed.

Helper receipt SHA-256:
`d3cb2ba58c95ebcb6762d0d63efde3e01c3451a74f89690c755cd1229fd1b329`.
The tested automatic consumer block matches the committed qualification helper.
UNC conversion has source review but no available-share runtime proof here.
These client checks do not establish native coverage for the model-only Core
consumer or qualify newer Main private C++ layouts. The separate full frozen
ReFS SDK run completed **72/84 PASS, 12 failures, zero skipped**; its failures
remain release/qualification work and are not changed into expected passes.


## November 9 full Linux normal run and post-finish resolution guard

Frozen `85085d8` passed **169/169 tests, zero skipped**, against a fresh
212-TU GCC 14 Debug/O1 build. Configure took 1.12 seconds, all 289 build steps
773.37 seconds, and tests 119.39 seconds. Source manifest SHA-256 is
`75c77c029955c38fbd77847504c04488f6df6e2a13a430f2d27c258e023175b4`.
The comparable earlier normal cohort took 577.56 seconds for 209 TUs/283 steps;
the larger current build overlapped other bounded single-CPU jobs. The verbose
compile log, exact outputs, timings and unchanged source receipt are retained;
this receipt excludes subsequent pending-writer and hierarchy changes.

The separate fully instrumented GCC 14 ASan/UBSan `45914b8` cohort completed
**159/169 tests, 10 failures, zero skipped**. Six failures are the older Tree
fixture expectations subsequently corrected in `85085d8`; two retry OOM aborts
remain under investigation. Two resolution tests exposed a genuine UBSan null
reference: after Session finish revokes `storage_root()`, `require_clean()`
dereferenced that empty shared pointer while checking the saved close error.

The guard now retains and checks the optional Root before reading it, then
returns the existing first close failure. The regression checks matching error
domain/code on repeated finish and post-finish assess, unchanged generation and
fresh recovery. No header or class layout changed. A controlled derivative of
the exact fully instrumented SDK rebuilt the production TU and strengthened
test TU (18.72 and 8.94 seconds), replacing just that static archive member.
Both affected binaries passed: **370 resolution checks** and the existing
POSIX consumed-close/recovery suite (**669 checks**, including its 369-check
resolution bundle). Their links took 0.67 seconds each and native runs 10.78
and 11.30 seconds. Original SDK sources, headers, libraries and both sanitizer
runtimes remained hash-identical; no normal/instrumented object mixing occurred.
The initial failure cohort remains immutable. This is focused sanitizer proof,
not a subsequent whole-suite or Windows/macOS qualification claim.


## Retry worker waits for a genuine pending first-error writer

A forced native interleaving reproduced two defects in the prior retry worker:
an early pending Root failure became a sticky Adapter placeholder, and a late
pending writer could coexist with public Complete/worker_drained. The fix tracks
pending writers separately, reserves their diagnostic priority and reads their
eventual native tuple. Core finish drains native owners once and returns a typed
provisional result immediately. Only the enclosing worker waits, after every
callback/finalizer has returned and outside locks, using allocation-free memory
readback while retaining the genuine Roots. Final Complete/drained publication
waits for the writer; cached/repeated calls never retry a consumed close.

Frozen packet manifest SHA-256:
`cf3492a20e929ac303419bb8e4f39a1335682cb7f440a99b84e55a218b30e30e`.
All packet files, four live baseline hashes, final hashes and narrow CMake hunks
were verified before integration. The failure-only compiled after-drain test seam
starts a real Root failure writer; it grants no native success or authority.
The unchanged public C ABI v1 remains, but the private retry class layout changes,
so every dependent translation unit and facade must be rebuilt coherently.

On native Linux ext4/noatime, GNU 14 O1 normal qualification passed **46 native
cases plus the existing retry suite**. Six new cases force early/late publication,
C++ explicit/destructor finish, distinct Roots and persistent allocation failure.
They require already-drained readers/journals while the first writer is paused,
no premature Complete/drained, eventual exact ENOSPC rather than later EIO, and
no close retry after descriptor reuse. The fresh baseline build took 454.88
seconds; all class-dependent candidate objects rebuilt in 20.52 seconds. Original
forced counterfailures and diagnostics are retained. This receipt does not
qualify Windows, Darwin or sanitizer execution; the two earlier sanitizer OOM
failures remain open and are being diagnosed against their immutable SDK.


## November 9 combined Linux ASan/UBSan retry and resolution qualification

A new immutable `78c7386` snapshot passed **175/175 default tests, zero skipped**,
with all 212 configured translation units instrumented by GCC 14 ASan/UBSan.
No NDEBUG, sanitizer exclusions or mixed normal objects were used. This includes
the six forced pending-writer cases, both formerly aborting OOM modes, the
post-finish resolution guard, Session close tests and reconciled Tree fixtures.
Configure took 1.28 seconds, the fresh 289-step build 1,165.04 seconds, and the
serial test suite 334.91 seconds. The comparable preceding 212-TU instrumented
build took 1,225.65 seconds. Source manifests, exact compile commands, outputs
and both runtime hashes were checked and retained.

The preceding `45914b8` cohort remains **159/169** in its original evidence.
A separate bounded investigation passed two unchanged-binary and ten diagnostic
runs of its two OOM cases without a recurrence, stall or sanitizer report. Their
historical SIGABRTs remain unexplained; the new passing cohort is independent
evidence, not a reinterpretation of those failures. No deadline was widened.

This combined receipt qualifies the stated Linux snapshot only. Hierarchical
Session relay, the later Windows rename/action patch, new archive ownership
work, Windows/macOS runtime matrices and ThreadSanitizer remain separate gates.


## Windows rename/action consumed-close errors and late Root publication

A qualified normal MSVC derivative fixes direct cursor rename and Action worker
close-error loss. Rename source/parent and published verification views explicitly
drain before success; worker-owned input/verification closes precede Complete
records, and cached Verified rows wait for final drainage. Native consumed-close
errors survive persistent allocation failure through fixed Root diagnostics,
prevent automatic retries, and cannot become successful cached results.

Independent review found a later window after the initial Root read but before
request-Root release. The final amendment retains that same genuine owner through
all finalizers, then performs post-drain pending-publication readback before its
release in normal and exception paths. No extra shared Root owner changes closure
semantics. Waiting occurs on the worker, outside callbacks/destructors and locks.
The generic pending-result formatter now uses its existing nonempty operation tag
to avoid MSVC Debug's allocating noexcept empty-string construction under OOM.

The sealed NTFS/ReFS derivative passed **126 native cases**: all 118 earlier
ordinary/raw UTF-16/long-path cases plus eight late-publication normal/OOM cases
covering both rename variants. Eight matched pre-fix runs reproduced premature
Finished/Verified while the genuine first writer was paused. The fixed worker
stayed nonterminal, then retained the exact original Win32 CRC 23 state/code/tag.
Journal Complete records already durable before an unrelated late Root-only
failure remain historical evidence; public cached success is still refused.
The consumer-close-before-Complete tests remain distinct and passed.

Packet manifest SHA-256:
`bc2426998cea9182c01475fec17b28cb210652134191116c98d7e5dc49d582f4`.
Combined patch SHA-256:
`905a82c6c79b664407d13b5e964a5e6e804626dd5df8d793500930c2104932bc`.
All packet hashes and exact apply contexts were verified. Existing public v1
headers/class layouts were unchanged in the qualified derivative. Its new Action
objects and shared fixture compiled in 44.46 seconds; the final diagnostic-only
fixture rebuild took 12.00 seconds. Its old matching SDK cohort is not the later
Main private Retry/Caller/Full/Session cohort.

`CK_CORE_FS_TEST_NATIVE_CLOSE_HOOKS=ON` now registers the 49 qualified mode names
for a selected native Windows fixture root. Compiled failure-only hooks always
call real CloseHandle first and cannot turn a real failure into success. This
new CMake registration still requires a fresh coherent Windows build/runtime
check. Hooks are off by default. No import-symbol replacement, IAT manipulation
or process-memory patching is used. Combined Linux/macOS/sanitizer qualification
of this increment is separate from the preceding 175-case receipt.


## November 10 current combined qualification checkpoint

The immutable `94579be` Linux normal snapshot passed **175/175 default tests,
zero skipped**. All 212 configured translation units rebuilt in a fresh serial
289-step GCC 14 Debug O1 build without NDEBUG. Configuration took 1.01 seconds,
build 614.11 seconds and tests 121.49 seconds. The preceding comparable clean
212-TU normal build took 773.37 seconds; actual compiled inputs and output
fingerprints, rather than elapsed time alone, establish freshness. Source bytes
were unchanged. This includes the late Action Root readback and generic pending
formatter; the earlier 175-case ASan/UBSan receipt remains tied to `78c7386`.

A separate coherent Windows `94579be` SDK rebuilt all 198 translation units in
262 steps (951.71 seconds compiling). The newly registered consumed-close tests
passed **49/49 on NTFS and 49/49 on ReFS**, with **28/28 long-path controls**.
All 157 installed headers matched source. Four installed consumers compiled;
only core passed at runtime. Platform, native and C API consumers each timed out
at the original 90-second deadline. The location remains unresolved. These tests
inherited the required filesystem name explicitly; CMake registration still
needs a self-contained environment fix. Legacy fault mechanisms were not run;
their replacement remains unfinished. Sealed packet manifest SHA-256:
`d7c4ea11a225beecafe5d760c0ba8993e9a53aab52a610f5249be8cfafaeb8b8`.

The current macOS backend `0fb7a09` ThreadSanitizer snapshot rebuilt all 187
configured translation units in 188.69 seconds with the matching LLVM 23.1.4
and previously qualified Darwin runtime. It passed **55/65 tests**, with ten
failures and zero skips in 43.67 seconds. No race warning or sanitizer runtime
check failure was reported; this is not a passing suite. Several native tests
expect publication or directory-atime capabilities that the macOS provider
explicitly refuses; each failure still requires an independently verified
capability-specific test or product correction. The original failures remain
preserved. Source and runtime hashes were unchanged.

None of these receipts qualifies the unmerged hierarchical relay, the new
archive writer, full Windows/macOS matrices, a newer CDE SDK pin, or Apply.


## November 10 guarded Windows fixture corrections

Four test files now use their previously native-qualified fixture corrections:
ordinary DOS/UNC CLI addresses cross the existing wide extended-path boundary;
already extended UTF-16 remains exact. Address-only controls cover reachable
UNC, long names, raw UTF-16 and trailing dot/space names without granting metadata
or publication authority. The corrected Seed derivative passed 5,912 ordinary and 5,821
Complete checks against its immutable `ac03959` SDK.

The Action containing-Root test observes the actual wrapper-nested parent and
checks the held fixture identity, instead of assuming a volume-root child. Its
native NTFS suite passed in 6.37 seconds. The progressive source-binding test
advances bounded validation (at most one read and 31 bytes per advance) until the
exact Changed result, preserving source bytes and requiring no destination or
journal effect. It passed 7,004 checks in 89.51 seconds within the existing
180-second deadline.

Every baseline/final file hash and all 17 referenced evidence hashes were
verified before applying the narrow patches. This is prior-SDK fixture evidence,
not a current whole-platform or sanitizer pass. Product guards are unchanged;
legacy Windows fault-seam migration and installed-consumer startup failures
remain open. See `qualification/windows-fixture-corrections-20261110.json` in
the source repository for exact manifests and scope.


## November 10 self-contained Windows close-test registration

The Windows CMake block now declares and validates its configured NTFS/ReFS
provider before registering the 49 compiled-hook close cases, and passes
`CK_FS_EXPECT_NATIVE_FS` explicitly through each test's environment. This removes
the previously recorded dependence on the parent shell's environment. The
configured provider must still match the actual native fixture filesystem.

An isolated registration derivative passed **49/49 NTFS and 49/49 ReFS tests,
zero skipped**, while the parent deliberately supplied an incorrect provider.
The fixture executable was the byte-identical qualified `94579be` binary; no
product recompile or newer-header mixture was represented as fresh evidence.
All packet hashes, CMake baseline/final hashes and both JUnit results were
verified before importing the one-file change. See
`qualification/windows-native-close-registration-20261110.json` in the source
repository. The three installed-consumer startup timeouts remain unresolved;
this configuration fix does not qualify that separate runtime gate.


## November 10 current macOS capability fixtures and TSan

The current `0be3748` product/private-header bytes with the final Mac fixture
corrections passed **65/65 default CTest entries, zero skipped**, under the
matching LLVM 23.1.4 and qualified Darwin v3 ThreadSanitizer runtime. A fresh
whole build compiled all 187 translation units in 158.26 seconds; tests took
45.98 seconds. Every object and executable was hashed before launch and checked
unchanged afterward, along with source and runtime hashes. No race warning or
runtime check failure was reported. The comparable 187-TU builds took 161.55
and 188.69 seconds; actual compilation and fingerprints establish freshness.

The eight test files now exercise exact Mac capability refusals instead of
expecting unsupported positive publication. Checks include unchanged source and
target identity/content/metadata, journal states without publication claims,
no replay on cached polling, native drainage, zero copied bytes and zero achieved
preservation fields. A failed C copy attempt counts one processed item. Tree
review can issue a receipt; execution admission still refuses the missing native
directory-atime capability before effects. Retention, capture, aliases, model
rules, cancellation and teardown retain their independent checks. Existing
Windows fixture corrections are preserved. No product guard, timeout, sanitizer
exclusion or CMake test registration changed.

The earlier 55/65 and 58/65 cohorts remain failures in their original evidence.
A subsequent repeated cohort failed 64/65 at `journal_scope.ancestor_changed`;
its cause remains unexplained. Passive native-stat diagnostics preserve return
values and errno, and a later passing cohort does not establish why that earlier
failure occurred. This receipt is a passing current cohort, not a claim that the
intermittent ancestry issue is fixed. Positive strong publication on macOS,
native-window acceptance, newer Windows/current combined SDKs and the unmerged
hierarchy/archive work remain separate gates. Exact records are in
`qualification/macos-capability-fixtures-20261110.json`.
