# Foundation qualification, 2026-11-02

This is a foundation checkpoint, not a completed preservation or two-way native
execution qualification.

macOS RelWithDebInfo output:
`/Volumes/S8T/tmp/ck-core-fs-lib-contract.rlIRSX/build/libck-core-fs-lib.0.2.0.dylib`.
Eight integrated CTest suites passed (3.53 seconds); the separately built,
installed C consumer passed (0.20 seconds). Tests include real worker copy,
event overflow/coalescing, cancellation and destruction, as well as comparison,
conflict, policy and baseline codec/state-machine coverage. Assertions remain
enabled in optimized tests.

The final changed-object build/test ran 18:37:23–18:37:29 UTC after a whitespace
cleanup in policy code. A preceding 18:36:36–18:36:37 UTC freshness check was an
expected no-op after the successful changed-object build and tests. Earlier
dependency rebuilds included modified native headers; source changes explained
their longer duration. No application was
launched. There are no separately bundled assets.

Compiled-input manifest digest (sorted source/include/tests/cmake/tools/workflow
file SHA-256 list):
`fde3d60877547e3f8a26031383cad62f53982168363d3a963ec66d283bf4fb50`.
Root CMake SHA-256:
`12b7f75e639a75008188c3330b222e158597afc37a0944528ed23f287a777fca`.
Output SHA-256:
`85672bda9a5ae7a4457db10d65875dcdb203cdc59d37e02071561977e3fb6d76`.

Independent agent checks: preservation assessment 271,422 checks; conflict rules
363 checks; baseline/reconciliation 1,574 ASan/UBSan checks. Comparison core and
C preview suites also passed standalone ASan/UBSan with warnings as errors.
These supplement, rather than replace, integrated/native acceptance.

The mandatory ordinary-scope native preserving-success gate **failed**:
`regular_metadata.unhandled_visible_attribute`, attribute `com.apple.provenance`,
role Opaque. No value was inspected or attribute removed. The negative/refusal
tests pass, but that does not qualify successful preserving copy. Complete
metadata preservation remains unavailable; Linux runtime ordinary preservation
and Windows security qualification remain outstanding for this revision.

CI now runs installed consumers and fully instrumented sanitizer jobs. macOS
qualification requires the configured self-hosted runner with approved temporary
volumes; hosted Linux/Windows results must be checked for the committed revision.
No host memory-security setting is weakened for sanitizer runs.

Remaining execution gates include native plan receipts/tree execution,
replacement/version retention, durable two-way session storage and overlapping
root locking, baseline/journal commit recovery, full security replay and
Trash/restore. The two-way codec/state machine alone supplies none of those.

## Preservation-report correction

The peer identified a real false qualification claim after this checkpoint.
Completed loss-consenting jobs bypass native inventory and caller-ownership
application. They now retain Unknown provider qualification and report no
caller UID/GID application for both legacy Complete and explicit Ordinary scope.
Individually applied/verified basic fields remain separate from scope coverage.
Available scope qualification requires successful completion through the path
that mandates inventory, staging qualification and prepublication checks.

Changed-object lifecycle target build/test: 18:40:47–18:40:54 UTC, seven seconds
(consistent with the recent incremental dependency scope). The threaded native
lifecycle regression passed in 3.06 seconds, including both loss-consent scope
variants. No app was launched; output path/configuration are unchanged.
Compiled-input manifest SHA-256:
`146d8729c3619abfc0e78daccc9c44e280fbce431598e40353019ff7d1f589f6`.
Output SHA-256:
`3e1e4fd99bc365fce320f2b7fa069eeedda6fb2260658cd99be560e22de40f96`.

## Independent Linux ARM64 installed-consumer qualification

The CDE peer reported an independently pinned run of
`1f0ce395dced405a6fa6f4033d2d43dd0edd7793`. The reused configured build rebuilt
116 Ninja steps in 99.053 seconds, consistent with the changed shared headers
and compile definitions. All eight core CTests passed in 11.686 seconds. The
pure C installed consumer configured, built and linked against the isolated
installed prefix, with the loaded library path verified using `ldd`.

Of twelve independent behavioral contracts, ten passed. Ordinary-scope copy
and cancellation used version-1 options with `allow_metadata_loss=0`. Successful
copy checked exact data, mode 0640, mtime 1000000001, effective UID/GID, reported
ordinary mode/atime/mtime preservation and Available provider qualification.
Invalid outputs, stale errors, metadata reset, job ownership, byte-native names,
held-parent rename/substitution, entry substitution and final-link policies also
passed. Cancellation remains a tiny-file completion/cancellation race test;
blocked-transfer latency is not established.

The two Complete-metadata copy/cancellation contracts failed at terminal
Unsupported, with zero achieved fields. Those are retained capability failures;
they do not qualify Complete preservation or identify a separate cancellation
defect. Local ordinary fixture success does not establish other providers,
recursive execution or durable two-way synchronization.

Installed `.so` 0.2.0 SHA-256 reported by the independent run:
`6e5c8fbd3129d52562e8f288d7987864d351acd0ba9b03bfad0de6a0002d7f4e`.
Remote evidence:
`/home/klukas/tmp/cde-hardening-20261102-01/fs-consumer-contracts/checkpoint-1f0ce39.json`.
The subsequent preservation-report fix `3efe038` requires its own pinned rerun;
these results are not attributed to that later revision.

## Independent report-fix rerun and harness integration

The peer separately pinned `3efe0381ed2983748ca0bef8c49e6075cf5f0951` on
Linux ARM64. Incremental build: 5.115 seconds, three compiled objects/nine Ninja
steps. All eight core suites passed in 6.403 seconds. The expanded fourteen
installed-C contracts produced twelve passes and two retained Complete-scope
preservation failures. Both loss-report contracts verified Unknown provider
qualification and zero caller UID/GID application, while verified basic fields
remained correct. Ordinary scope with loss disabled still passed its copy and
cancellation cases.

Peer-reported installed library SHA-256:
`f7d6be27ee7b4cc12f6d5e63447e531b95fb6f0a7ae00f2fd7205d39d61cfb13`.
Evidence: `checkpoint-3efe038.json` and `3efe038-contracts.log` in the same
remote qualification root listed above.

The independent standalone harness was reviewed and integrated from peer commit
`ba4e378a357d2bcb5e9e166caf564dc89f4a3847`. It uses only the installed C ABI;
Windows filesystem fixtures remain separately unqualified. No preservation
success gate is reclassified as an expected pass or substituted for a loss test.

The owner ran the imported harness on macOS against installed report-fix output
SHA-256 `3e1e4fd99bc365fce320f2b7fa069eeedda6fb2260658cd99be560e22de40f96`.
It configured/compiled as C and ran fourteen contracts in 1.02 seconds: nine
passed, four preservation-success cases failed as Unsupported, and the raw-byte
fixture skipped only on native EILSEQ. Both loss-report regressions passed. The
ordinary/Complete preservation failures remain capability gaps; no broad native
mutation or cancellation-latency qualification follows from these results.

## 0.3 development integration snapshot

The new native composition, metadata replay, durable sessions, and C action
interfaces built together on macOS with unchanged inputs from
19:40:40.972 to 19:43:08.909 UTC (147.937 seconds). The preceding comparable
clean build took 136.088 seconds; logs show all new translation units and
native suites compiled. This was a coherent build after rejecting an earlier
run whose C++ result layouts changed during compilation. No sanitizer finding
was suppressed and no mixed-layout run was counted as qualification.

Source/include/tests/root-CMake snapshot SHA-256:
`3e418f041d240be4f5d8c778aec5a623b51ee994d1387698bb61c35aa08612b1`.
Library output:
`/Volumes/S8T/tmp/ck-core-fs-lib-contract.rlIRSX/build/libck-core-fs-lib.0.3.0.dylib`.
Output SHA-256:
`a55c788e61008691e460e5d1b3c4dd7950106c64ed0f811efbd72fef616e22fa`.

After two test-only corrections (earlier retention refusal and a unique
per-run journal fixture), all 17 integrated suites passed in 5.22 seconds.
The added suites cover native C copy/stale/cancel/keep-both, ACL/xattr replay,
601 reviewed-tree checks, 2,351 session checks, action receipts/retries, and
retention journal-flush fault boundaries. An installed C-only consumer also
configured, built, and passed. The 13-page ckdocs site built strictly with no
warnings.

These are development results, not final qualification of 0.3. Subsequent
static review identified Windows staging/mapping exclusion, Trash ancestry/
inheritance/identity continuity, Darwin coordinator ACL/mount privacy,
history-loss handling, and absence-proof budget issues. The affected paths
require fixes and fresh qualification. Passing happy-path and injected-fault
suites did not establish those missing guarantees.

Remaining feature gates include directory-level two-way convergence, actual
crash retry/resume authority, Windows additional data streams and some security
metadata, and destructive POSIX operations without an object-conditional
primitive. A typed refusal is recorded as a capability limit, not successful
implementation of that feature. Development records live under the same
temporary root as `frozen-build.json`, `checkpoint-tests.json`, and their logs.

## Post-review native integration checkpoint

The coherent macOS clean build ran 20:48:46–20:51:06 UTC (140 seconds),
consistent with the preceding 148-second clean build. It compiled all changed
native modules. Its first test run found one fixture assertion error: the
negative NoOwners test rejected the approved `/Volumes/S8T/tmp` root itself
while accepting its descendants. The corrected assertion still requires an
approved volume and leaves ownership/ACL refusal checks intact.

The subsequent worker-drained API and fixture changes were rebuilt and tested
with unchanged inputs. Final verification ran 20:58:44–20:58:58 UTC: a
4.667-second incremental build recompiled the session fixture; all 17 suites
passed in 5.71 seconds. The worker-drained implementation and its C tests had
already compiled in the immediately preceding changed-object build. All four
native tree C cases passed with explicit shutdown-drain checks. The installed
C-only smoke consumer passed, and the independent installed-C harness passed
13 behavioral contracts with one raw-byte-name fixture skipped on native
EILSEQ. Both ordinary and Complete preservation-success cases passed on these
specific APFS fixtures. This does not establish every metadata namespace or
provider. The 13-page documentation site also built strictly without warnings.

Source/include/tests/cmake/tools/workflows manifest SHA-256:
`7ef23fb381b6924659380a5969d3208b037cedd247d8621ff35b21335247cd2c`.
Library SHA-256:
`fb351e2df9f476f9d3d334c50df2ad7ba979cc62f87c75d64d8b3c887df08a2f`.
Output is `post-hardening/build/libck-core-fs-lib.0.3.0.dylib` beneath the
development evidence root above. Positive native fixtures used the
ownership-enforcing PRO-BLADE volume; S8T's NoOwners mode was exercised only
as a negative private-storage fixture. No mount setting was changed.

This checkpoint adds reviewed native tree execution, strict metadata replay,
durable session storage/locks/verified commits, and C action interfaces. It
does **not** close all requested feature gates. Outstanding work includes
native two-way execution composition, directory metadata convergence, actual
copy retry/resume, Windows alternate streams and qualified immutable-content
guards, safe POSIX publication/destructive primitives, and explicit reporting
of delayed writable-handle/journal close failures. Worker-drained currently
proves no remaining backend I/O; it does not repair destructor-only close-error
reporting. Frontend execution remains gated pending these fixes and pinned
cross-platform qualification. No release tag or blanket preservation claim
is made from this checkpoint.

### Complete-scope report review

Independent consumer review found that the passing Complete-copy cases above
checked basic bytes/mode/times but did not require the report's logical-security
coverage. `LABELS_CAPABILITIES` remained Unknown while provider qualification
was incorrectly promoted to Available. Therefore those cases do **not**
qualify Complete logical preservation. The provider report is being corrected
to require every requested logical class; native Complete capture must also
refuse before mutation until its security-label/capability coverage is proved.
No successful basic-copy test or blanket flag change supplies that proof.

## Fallible finalization and held-object publication checkpoint

An immutable copy of the integrated hardening inputs built on macOS from
21:35:25 to 21:37:37 UTC (132 seconds), consistent with the preceding
140-second clean build. Every compiled input still matched the live source
after the run. Source manifest SHA-256:
`bd2f2e7ffbd59b80831df1711447268484020be95952c8b009ac045143aa059d`.
Library SHA-256:
`ef05b6d846d8f88531a103af29d62b563bbd0dde23f2322076aa07876a19603f`.
Evidence is `/Volumes/S8T/tmp/ck-core-fs-hardening.6j2hcco1/qualification`.

The complete macOS run is **FAILED: 15 of 20 suites passed**. The five failures
are positive copy gates (`regular_metadata`, `job_lifecycle`, `tree_c_copy`,
`tree_c_keepboth`, `reviewed_tree_plan`), all refusing the unqualified macOS
publication primitive. They remain failures, not skips or expected passes.
The passing suites include idle-review pause/resume, cancellation of a queued
review, explicit worker drain, metadata/writer finalization, durable session
close faults, action close faults, and retained-target close-failure handling.
No app was launched from this partially qualified output.

Two isolated, fully instrumented focused tests also passed ASan/UBSan with
warnings as errors: destination-close failure before source retirement, and
recovery-evidence versions 1–6 including every truncated prefix and anonymous
name-hint rejection. Their records are beneath
`/Volumes/S8T/tmp/ck-core-fs-close.n40qkin9` and
`/Volumes/S8T/tmp/ck-core-fs-codec.uzvqhgqj`. They do not replace a fully
instrumented integration run. The CI-reported duplicate native RTTI problem
was corrected by removing duplicate implementations from mixed C/C++ test
processes; sanitizer checks were not disabled.

The independent metadata owner additionally qualified actual Windows ReFS
writer closure and the integrity-label replay fix, including preserving an
already-exact implicit label without creating a present-null SACL. That focused
run does not qualify the subsequently changed journal-parent flush protocol,
NTFS, two-way execution, or replacement content guards. Complete logical
security coverage, macOS publication, native prefix resume, directory replay
and full mixed-direction execution remain open. Frontend mutation enablement
and a release tag remain blocked on those requirements.

## Read-only Compare receipt correction

Compare keeps every row a Report even when conflict rules request Ask,
replacement retention, or nonempty-target protection. These preferences remain
visible in the assessment; they cannot authorize mutations. Invalid rules,
revoked receipts, foreign instances and reuse by Copy/Sync still refuse.
The C worker does not prepare or change permissions on a mutation journal root
for Compare.

The isolated macOS incremental build took 14.21 seconds (only the reviewed-tree
core, C worker and their tests changed). All five focused suites passed:
`reviewed_tree_compare`, `tree_c_compare`, `tree_c_stale`, `tree_c_cancel`,
and `tree_c_cancelreview`. The actual C worker exercised Complete + Ask +
retain/protect, verified unchanged target bytes and journal-root permissions,
and waited for worker drain. This qualifies read-only Compare only; it does
not qualify Complete metadata preservation or mutation publication.
Input hashes and build/test timestamps are recorded in
`/Volumes/S8T/tmp/ck-core-fs-hardening.6j2hcco1/compare-record.json`.

The follow-up C boundary accepts Compare with an empty journal root and a zero
operation ID, without parsing or validating either mutation-only field. The
same five suites passed again; the C test additionally proves Copy and Sync
reject both missing IDs and missing journal roots. Evidence is
`/Volumes/S8T/tmp/ck-core-fs-hardening.6j2hcco1/compare-no-journal-record.json`.
