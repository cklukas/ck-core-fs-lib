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
