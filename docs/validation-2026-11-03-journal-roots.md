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
| Complete matching Root11 Linux sanitizer qualification | Pending final review |
| Complete matching Root11 Windows ASan qualification | Pending corrected harness rebuild |
| Complete matching Root11 macOS TSan qualification | Pending qualified runtime and full rebuild |
| Actual Linux XFS/Btrfs runtime qualification | Pending |

The Windows ASan attempt failed during compilation. Its flags omitted C++
exception-unwind support; that attempt is invalid qualification evidence and
must be replaced by a complete matching rebuild. It is not counted as a
product sanitizer finding or a passing run.

The macOS failures are `regular_metadata`, `job_lifecycle`, `tree_c_copy`,
`tree_c_keepboth`, and `reviewed_tree_plan`. Strong descriptor-bound staging
publication remains unsupported. These mandatory positive tests are retained;
they are not suppressed, skipped, or relabeled as passes.

The stock macOS TSan runtimes report a race in a standalone detached-thread
test that writes only native thread-local `errno`. A pinned runtime correction
is being qualified separately, including deliberate races and byte-precise
shadow tests. A corrected-runtime result will be identified by its exact
compiler/runtime source and binary hashes; it cannot establish a stock-runtime
pass.

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
before compiling; its subsequent full qualification results remain required.
