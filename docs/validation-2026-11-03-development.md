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
