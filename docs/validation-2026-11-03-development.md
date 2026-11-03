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

The later coherent Windows and macOS integration runs still fail Tree receipt
validation after publication. Passing source and metadata components therefore
do not establish receipt-bound execution completion. The Linux mount candidate
passed ext4 and XFS but exposed a real Btrfs identity-domain bug: statmount's
superblock device is distinct from the held object's VFS device. Its correction
retains and revalidates both domains separately; a fresh coherent three-filesystem
run is required before counting that correction as qualified.

## Remaining gates

- Integrate and qualify postorder directory metadata replay and bounded
  regular-file metadata execution against the exact reviewed evidence.
- Qualify Windows named conflict resolution and all-stream admission.
- Complete native Linux mount-ancestry qualification on ext4, XFS and Btrfs.
- Retain the macOS strong-publication failures until a suitable native
  primitive is available and qualified.
- Qualify the final coherent SDK with its installed C consumers and matching
  sanitizers before changing frontend pins or release tags.

The proposed ckgit runner remains disabled. Its observed job bind topology
currently fails the native ancestry guard, and the installed runner lacks
project-specific job admission. A configured workflow alone is not running CI.
